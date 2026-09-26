/* SPDX-License-Identifier: GPL-2.0-only */
#include "radio_linux.h"
#include "radiolib_backend.h"

#include <errno.h>
#include <fcntl.h>
#include <gpiod.h>
#include <linux/spi/spidev.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define RADIO_CONSUMER "remote-tester-radio"

static int line_set(struct gpiod_line *line, int value)
{
	return line ? gpiod_line_set_value(line, value) : -EINVAL;
}

static int switch_idle(void *context)
{
	struct radio_linux *radio = context;
	int err = line_set(radio->txen, 0);
	return err ? err : line_set(radio->rxen, 0);
}

static int idle_readback(void *context)
{
	struct radio_linux *radio = context;
	if (gpiod_line_get_value(radio->txen) != 0 || gpiod_line_get_value(radio->rxen) != 0)
		return -EIO;
	return 0;
}

static int reset_low(void *context)
{
	return line_set(((struct radio_linux *)context)->reset, 0);
}

static int standby_rc(void *context)
{
	return radiolib_backend_standby_rc(context);
}

static struct gpiod_chip *open_chip(const char *gpiochip)
{
	return !strncmp(gpiochip, "/dev/", 5) ? gpiod_chip_open(gpiochip) : gpiod_chip_open_by_name(gpiochip);
}

int radio_linux_open(struct radio_linux *radio, const char *spidev, const char *gpiochip,
	const struct radio_lines *lines, const struct radio_config *config)
{
	uint8_t mode = SPI_MODE_0;
	uint8_t bits = 8;
	bool reset_requested = false;
	bool txen_requested = false;
	bool rxen_requested = false;
	int err = 0;

	if (!radio || !spidev || !gpiochip || !lines || !lines->reset || !lines->busy ||
	    !lines->dio1 || !lines->txen || !lines->rxen || radio_config_validate(config))
		return -EINVAL;
	memset(radio, 0, sizeof(*radio));
	radio->spi_fd = -1;
	radio->spi_hz = config->spi_hz;
	radio->spi_fd = open(spidev, O_RDWR | O_CLOEXEC);
	if (radio->spi_fd < 0)
		return -errno;
	if (ioctl(radio->spi_fd, SPI_IOC_WR_MODE, &mode) ||
	    ioctl(radio->spi_fd, SPI_IOC_WR_BITS_PER_WORD, &bits) ||
	    ioctl(radio->spi_fd, SPI_IOC_WR_MAX_SPEED_HZ, &radio->spi_hz))
		goto fail;
	radio->chip = open_chip(gpiochip);
	if (!radio->chip)
		goto fail;
	radio->reset = gpiod_chip_find_line(radio->chip, lines->reset);
	radio->busy = gpiod_chip_find_line(radio->chip, lines->busy);
	radio->dio1 = gpiod_chip_find_line(radio->chip, lines->dio1);
	radio->txen = gpiod_chip_find_line(radio->chip, lines->txen);
	radio->rxen = gpiod_chip_find_line(radio->chip, lines->rxen);
	if (!radio->reset || !radio->busy || !radio->dio1 || !radio->txen || !radio->rxen)
		goto fail;
	if (gpiod_line_request_output(radio->reset, RADIO_CONSUMER, 0))
		goto fail;
	reset_requested = true;
	if (gpiod_line_request_output(radio->txen, RADIO_CONSUMER, 0))
		goto fail;
	txen_requested = true;
	if (gpiod_line_request_output(radio->rxen, RADIO_CONSUMER, 0))
		goto fail;
	rxen_requested = true;
	if (gpiod_line_request_input(radio->busy, RADIO_CONSUMER) ||
	    gpiod_line_request_rising_edge_events(radio->dio1, RADIO_CONSUMER))
		goto fail;
	err = radiolib_backend_create(radio);
	if (err)
		goto fail;
	return 0;

fail:
	if (!err)
		err = errno ? -errno : -EIO;
	if (txen_requested)
		(void)line_set(radio->txen, 0);
	if (rxen_requested)
		(void)line_set(radio->rxen, 0);
	if (reset_requested)
		(void)line_set(radio->reset, 0);
	radio_linux_close(radio);
	return err;
}

void radio_linux_close(struct radio_linux *radio)
{
	if (!radio)
		return;
	radiolib_backend_destroy(radio);
	if (radio->reset)
		gpiod_line_release(radio->reset);
	if (radio->busy)
		gpiod_line_release(radio->busy);
	if (radio->dio1)
		gpiod_line_release(radio->dio1);
	if (radio->txen)
		gpiod_line_release(radio->txen);
	if (radio->rxen)
		gpiod_line_release(radio->rxen);
	if (radio->chip)
		gpiod_chip_close(radio->chip);
	if (radio->spi_fd >= 0)
		close(radio->spi_fd);
	memset(radio, 0, sizeof(*radio));
	radio->spi_fd = -1;
}

int radio_linux_set_frequency(struct radio_linux *radio, uint32_t frequency_mhz)
{
	int err;
	if (!radio || frequency_mhz < 410 || frequency_mhz > 490)
		return -EINVAL;
	err = radiolib_backend_set_frequency(radio, frequency_mhz);
	if (err && err != -EINVAL) {
		radio->faulted = true;
		(void)radio_linux_cleanup(radio);
	}
	return err;
}

int radio_linux_configure(struct radio_linux *radio, const struct radio_config *config, uint8_t payload_len)
{
	struct radio_cleanup_ops ops = { standby_rc, switch_idle, idle_readback, reset_low };
	int err;
	if (!radio || radio_config_validate(config) || !payload_len || payload_len > sizeof(radio->last_rx))
		return -EINVAL;
	radio->configured = false;
	radio->network_tx_allowed = false;
	radio->faulted = false;
	radio->last_rx_len = 0;
	radio->last_irq = 0;
	err = radiolib_backend_configure(radio, config);
	if (err) {
		radio->faulted = true;
		(void)radio_cleanup(&ops, radio, &radio->faulted);
		radio->faulted = true;
		return err;
	}
	radio->configured = true;
	radio->faulted = false;
	err = radio_cleanup(&ops, radio, &radio->faulted);
	if (err) {
		radio->faulted = true;
		return err;
	}
	return 0;
}

int radio_linux_probe(struct radio_linux *radio, const struct radio_config *config)
{
	uint8_t chip_mode = 0;
	uint8_t command_status = 0;
	uint16_t sync_word = 0;
	int err;
	if (!radio || !config)
		return -EINVAL;
	err = radio_linux_configure(radio, config, sizeof(radio->last_rx));
	if (!err)
		err = radiolib_backend_diagnostics(radio, &chip_mode, &command_status, &sync_word);
	if (!err) {
		radio->last_chip_mode = chip_mode;
		radio->last_command_status = command_status;
		radio->last_sync_word = sync_word;
		if (sync_word != config->sync_word)
			err = -EIO;
	}
	if (radio_linux_cleanup(radio))
		err = -EIO;
	if (err)
		radio->faulted = true;
	return err;
}

int radio_linux_start_receive(struct radio_linux *radio, uint8_t payload_len, bool continuous)
{
	int err;
	if (!radio || !radio->configured || radio->faulted)
		return -ENODEV;
	if (!payload_len || payload_len > sizeof(radio->last_rx))
		return -EINVAL;
	radio->last_rx_len = 0;
	radio->last_irq = 0;
	radio->cad_result_valid = false;
	err = radiolib_backend_start_receive(radio, payload_len, continuous);
	if (err) {
		radio->faulted = true;
		(void)radio_linux_cleanup(radio);
	}
	return err;
}

int radio_linux_start_tx_test(struct radio_linux *radio)
{
	int err;
	if (!radio || !radio->configured || radio->faulted)
		return -ENODEV;
	radio->last_irq = 0;
	radio->last_rx_len = 0;
	radio->cad_result_valid = false;
	err = radiolib_backend_start_transmit(radio,
		(const uint8_t *)RADIO_TX_PAYLOAD, RADIO_TX_PAYLOAD_LEN);
	if (err) {
		radio->faulted = true;
		(void)radio_linux_cleanup(radio);
	}
	return err;
}

int radio_linux_set_network_tx_allowed(struct radio_linux *radio, bool allowed)
{
	if (!radio)
		return -EINVAL;
	if (allowed && (!radio->configured || radio->faulted))
		return -ENODEV;
	radio->network_tx_allowed = allowed;
	return 0;
}

int radio_linux_start_transmit(struct radio_linux *radio, const uint8_t *data, size_t len)
{
	int err;
	if (!radio || !data || !len || len > sizeof(radio->last_rx))
		return -EINVAL;
	if (!radio->configured || radio->faulted)
		return -ENODEV;
	if (!radio->network_tx_allowed)
		return -EACCES;
	radio->last_irq = 0;
	radio->last_rx_len = 0;
	radio->cad_result_valid = false;
	err = radiolib_backend_start_transmit(radio, data, len);
	if (err) {
		radio->faulted = true;
		(void)radio_linux_cleanup(radio);
	}
	return err;
}

int radio_linux_start_cad(struct radio_linux *radio)
{
	int err;
	if (!radio || !radio->configured || radio->faulted)
		return -ENODEV;
	radio->last_irq = 0;
	radio->last_rx_len = 0;
	radio->cad_result_valid = false;
	radio->last_cad_busy = false;
	err = radiolib_backend_start_cad(radio);
	if (err) {
		radio->faulted = true;
		(void)radio_linux_cleanup(radio);
	}
	return err;
}

int radio_linux_cad_result(struct radio_linux *radio, bool *busy)
{
	if (!radio || !busy)
		return -EINVAL;
	if (!radio->configured || radio->faulted)
		return -ENODEV;
	if (!radio->cad_result_valid)
		return -EAGAIN;
	*busy = radio->last_cad_busy;
	return 0;
}

int radio_linux_sample_rssi(struct radio_linux *radio, int16_t *rssi_dbm)
{
	if (!radio || !rssi_dbm)
		return -EINVAL;
	return radiolib_backend_sample_rssi(radio, rssi_dbm);
}

int radio_linux_handle_irq(struct radio_linux *radio, uint16_t *irq)
{
	int err;
	if (!radio || !radio->configured || radio->faulted)
		return -ENODEV;
	err = radiolib_backend_handle_irq(radio, irq);
	if (err && err != -EOVERFLOW) {
		radio->faulted = true;
		(void)radio_linux_cleanup(radio);
	}
	return err;
}

int radio_linux_cleanup(struct radio_linux *radio)
{
	struct radio_cleanup_ops ops = { standby_rc, switch_idle, idle_readback, reset_low };
	int err;
	if (!radio)
		return -EINVAL;
	err = radio_cleanup(&ops, radio, &radio->faulted);
	if (radio->faulted)
		radio->network_tx_allowed = false;
	return err;
}
