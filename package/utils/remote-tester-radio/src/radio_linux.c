/* SPDX-License-Identifier: GPL-2.0-only */
#include "radio_linux.h"
#include "vendor/sx126x/sx126x.h"
#include "vendor/sx126x/sx126x_hal.h"
#include <errno.h>
#include <fcntl.h>
#include <gpiod.h>
#include <linux/spi/spidev.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <time.h>
#include <unistd.h>

#define RADIO_CONSUMER "remote-tester-radio"
#define BUSY_TIMEOUT_MS 500U
#define LORA_SYNC_REGISTER 0x0740U

static void delay_ms(unsigned int ms)
{
	struct timespec delay = { ms / 1000, (ms % 1000) * 1000000L };
	nanosleep(&delay, NULL);
}

static int line_set(struct gpiod_line *line, int value)
{
	return line ? gpiod_line_set_value(line, value) : -EINVAL;
}

static int wait_busy_low(const struct radio_linux *radio)
{
	unsigned int elapsed;
	for (elapsed = 0; elapsed < BUSY_TIMEOUT_MS; elapsed++) {
		if (gpiod_line_get_value(radio->busy) == 0)
			return 0;
		delay_ms(1);
	}
	return -ETIMEDOUT;
}

static int spi_transfer(const struct radio_linux *radio, const uint8_t *command, uint16_t command_length,
	const uint8_t *write_data, uint8_t *read_data, uint16_t data_length, bool wait_before)
{
	struct spi_ioc_transfer xfers[2] = { 0 };
	int transferred;
	int expected = command_length + data_length;

	if (wait_before && wait_busy_low(radio))
		return -ETIMEDOUT;
	xfers[0].tx_buf = (unsigned long)command;
	xfers[0].len = command_length;
	xfers[0].speed_hz = radio->spi_hz;
	if (data_length) {
		xfers[1].tx_buf = (unsigned long)write_data;
		xfers[1].rx_buf = (unsigned long)read_data;
		xfers[1].len = data_length;
		xfers[1].speed_hz = radio->spi_hz;
	}
	transferred = ioctl(radio->spi_fd, SPI_IOC_MESSAGE(data_length ? 2 : 1), xfers);
	if (transferred != expected)
		return transferred < 0 ? -errno : -EIO;
	return wait_busy_low(radio);
}

sx126x_hal_status_t sx126x_hal_write(const void *context, const uint8_t *command, const uint16_t command_length,
	const uint8_t *data, const uint16_t data_length)
{
	return spi_transfer(context, command, command_length, data, NULL, data_length, true) ?
		SX126X_HAL_STATUS_ERROR : SX126X_HAL_STATUS_OK;
}

sx126x_hal_status_t sx126x_hal_read(const void *context, const uint8_t *command, const uint16_t command_length,
	uint8_t *data, const uint16_t data_length)
{
	return spi_transfer(context, command, command_length, NULL, data, data_length, true) ?
		SX126X_HAL_STATUS_ERROR : SX126X_HAL_STATUS_OK;
}

sx126x_hal_status_t sx126x_hal_reset(const void *context)
{
	struct radio_linux *radio = (struct radio_linux *)context;
	if (line_set(radio->reset, 0))
		return SX126X_HAL_STATUS_ERROR;
	delay_ms(20);
	if (line_set(radio->reset, 1))
		return SX126X_HAL_STATUS_ERROR;
	delay_ms(10);
	return wait_busy_low(radio) ? SX126X_HAL_STATUS_ERROR : SX126X_HAL_STATUS_OK;
}

sx126x_hal_status_t sx126x_hal_wakeup(const void *context)
{
	uint8_t command = 0xc0;
	/* The radio may be asleep with BUSY asserted: only wait after GetStatus. */
	return spi_transfer(context, &command, 1, NULL, NULL, 0, false) ?
		SX126X_HAL_STATUS_ERROR : SX126X_HAL_STATUS_OK;
}

static int standby_rc(void *context)
{
	return sx126x_set_standby(context, SX126X_STANDBY_CFG_RC) == SX126X_STATUS_OK ? 0 : -EIO;
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

static int sxok(sx126x_status_t status)
{
	return status == SX126X_STATUS_OK ? 0 : -EIO;
}

static sx126x_lora_bw_t bandwidth_from_khz(uint32_t bandwidth_khz)
{
	return bandwidth_khz == 125 ? SX126X_LORA_BW_125 :
		bandwidth_khz == 250 ? SX126X_LORA_BW_250 : SX126X_LORA_BW_500;
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
	int err;

	if (radio_config_validate(config) || !lines)
		return -EINVAL;
	memset(radio, 0, sizeof(*radio));
	radio->spi_fd = -1;
	radio->spi_hz = config->spi_hz;
	radio->spi_fd = open(spidev, O_RDWR | O_CLOEXEC);
	if (radio->spi_fd < 0)
		return -errno;
	if (ioctl(radio->spi_fd, SPI_IOC_WR_MODE, &mode) || ioctl(radio->spi_fd, SPI_IOC_WR_BITS_PER_WORD, &bits) ||
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
	if (gpiod_line_request_output(radio->reset, RADIO_CONSUMER, 0)) goto fail;
	reset_requested = true;
	if (gpiod_line_request_output(radio->txen, RADIO_CONSUMER, 0)) goto fail;
	txen_requested = true;
	if (gpiod_line_request_output(radio->rxen, RADIO_CONSUMER, 0)) goto fail;
	rxen_requested = true;
	if (gpiod_line_request_input(radio->busy, RADIO_CONSUMER) ||
	    gpiod_line_request_rising_edge_events(radio->dio1, RADIO_CONSUMER))
		goto fail;
	return 0;

fail:
	err = errno ? -errno : -EIO;
	if (txen_requested) (void)line_set(radio->txen, 0);
	if (rxen_requested) (void)line_set(radio->rxen, 0);
	if (reset_requested) (void)line_set(radio->reset, 0);
	radio_linux_close(radio);
	return err;
}

void radio_linux_close(struct radio_linux *radio)
{
	if (radio->reset) gpiod_line_release(radio->reset);
	if (radio->busy) gpiod_line_release(radio->busy);
	if (radio->dio1) gpiod_line_release(radio->dio1);
	if (radio->txen) gpiod_line_release(radio->txen);
	if (radio->rxen) gpiod_line_release(radio->rxen);
	if (radio->chip) gpiod_chip_close(radio->chip);
	if (radio->spi_fd >= 0) close(radio->spi_fd);
	memset(radio, 0, sizeof(*radio));
	radio->spi_fd = -1;
}

int radio_linux_set_frequency(struct radio_linux *radio, uint32_t frequency_mhz)
{
	if (frequency_mhz < 410 || frequency_mhz > 490)
		return -EINVAL;
	return sxok(sx126x_set_rf_freq(radio, frequency_mhz * 1000000U));
}

int radio_linux_configure(struct radio_linux *radio, const struct radio_config *config, uint8_t payload_len)
{
	sx126x_mod_params_lora_t mod;
	sx126x_pkt_params_lora_t packet;
	sx126x_pa_cfg_params_t pa = { 0x04, 0x07, 0x00, 0x01 };
	uint8_t sync[2] = { config->sync_word >> 8, config->sync_word & 0xff };

	if (radio_config_validate(config) || payload_len == 0 || payload_len > sizeof(radio->last_rx))
		return -EINVAL;
	mod.sf = (sx126x_lora_sf_t)config->spreading_factor;
	mod.bw = bandwidth_from_khz(config->bandwidth_khz);
	mod.cr = (sx126x_lora_cr_t)(config->coding_rate - 4);
	mod.ldro = radio_ldro_required(config->spreading_factor, config->bandwidth_khz);
	packet.preamble_len_in_symb = 8;
	packet.header_type = SX126X_LORA_PKT_EXPLICIT;
	packet.pld_len_in_bytes = payload_len;
	packet.crc_is_on = true;
	packet.invert_iq_is_on = false;
	if (sxok(sx126x_reset(radio)) || sxok(sx126x_set_standby(radio, SX126X_STANDBY_CFG_RC)) ||
	    sxok(sx126x_set_dio3_as_tcxo_ctrl(radio, SX126X_TCXO_CTRL_3_3V, 320)) ||
	    sxok(sx126x_set_reg_mode(radio, SX126X_REG_MODE_DCDC)) || sxok(sx126x_cal(radio, SX126X_CAL_ALL)) ||
	    sxok(sx126x_cal_img_in_mhz(radio, 410, 490)) || sxok(sx126x_set_dio2_as_rf_sw_ctrl(radio, false)) ||
	    sxok(sx126x_set_pkt_type(radio, SX126X_PKT_TYPE_LORA)) || radio_linux_set_frequency(radio, config->frequency_mhz) ||
	    sxok(sx126x_set_lora_mod_params(radio, &mod)) || sxok(sx126x_set_lora_pkt_params(radio, &packet)) ||
	    sxok(sx126x_write_register(radio, LORA_SYNC_REGISTER, sync, sizeof(sync))) || sxok(sx126x_set_pa_cfg(radio, &pa)) ||
	    sxok(sx126x_set_tx_params(radio, -9, SX126X_RAMP_200_US)) || sxok(sx126x_set_buffer_base_address(radio, 0, 0)) ||
	    sxok(sx126x_set_dio_irq_params(radio, SX126X_IRQ_ALL, SX126X_IRQ_ALL, SX126X_IRQ_NONE, SX126X_IRQ_NONE))) {
		(void)radio_linux_cleanup(radio);
		radio->faulted = true;
		return -EIO;
	}
	radio->configured = true;
	radio->faulted = false;
	return 0;
}

int radio_linux_probe(struct radio_linux *radio, const struct radio_config *config)
{
	sx126x_chip_status_t status;
	uint8_t sync[2];
	int err = radio_linux_configure(radio, config, 240);

	if (!err) err = sxok(sx126x_get_status(radio, &status));
	if (!err) {
		radio->last_chip_mode = status.chip_mode;
		radio->last_command_status = status.cmd_status;
	}
	if (!err) err = sxok(sx126x_read_register(radio, LORA_SYNC_REGISTER, sync, sizeof(sync)));
	if (!err) radio->last_sync_word = ((uint16_t)sync[0] << 8) | sync[1];
	if (!err && radio->last_sync_word != config->sync_word) err = -EIO;
	if (radio_linux_cleanup(radio)) err = -EIO;
	if (err) radio->faulted = true;
	return err;
}

int radio_linux_start_receive(struct radio_linux *radio, uint8_t payload_len, bool continuous)
{
	sx126x_pkt_params_lora_t packet = { 8, SX126X_LORA_PKT_EXPLICIT, payload_len, true, false };
	if (!radio->configured || radio->faulted)
		return -ENODEV;
	if (payload_len == 0 || payload_len > sizeof(radio->last_rx) || line_set(radio->txen, 1) || line_set(radio->rxen, 0) ||
	    sxok(sx126x_clear_irq_status(radio, SX126X_IRQ_ALL)) || sxok(sx126x_set_lora_pkt_params(radio, &packet)))
		return -EIO;
	return sxok(sx126x_set_rx_with_timeout_in_rtc_step(radio,
		continuous ? SX126X_RX_CONTINUOUS : SX126X_RX_SINGLE_MODE));
}

int radio_linux_start_tx_test(struct radio_linux *radio)
{
	sx126x_pkt_params_lora_t packet = { 8, SX126X_LORA_PKT_EXPLICIT, RADIO_TX_PAYLOAD_LEN, true, false };
	if (!radio->configured || radio->faulted)
		return -ENODEV;
	if (line_set(radio->txen, 0) || line_set(radio->rxen, 1) || sxok(sx126x_clear_irq_status(radio, SX126X_IRQ_ALL)) ||
	    sxok(sx126x_set_lora_pkt_params(radio, &packet)) ||
	    sxok(sx126x_write_buffer(radio, 0, (const uint8_t *)RADIO_TX_PAYLOAD, RADIO_TX_PAYLOAD_LEN)))
		return -EIO;
	return sxok(sx126x_set_tx(radio, 2000));
}

int radio_linux_sample_rssi(struct radio_linux *radio, int16_t *rssi_dbm)
{
	return sxok(sx126x_get_rssi_inst(radio, rssi_dbm));
}

int radio_linux_handle_irq(struct radio_linux *radio, uint16_t *irq)
{
	sx126x_rx_buffer_status_t buffer;
	sx126x_pkt_status_lora_t packet;
	sx126x_irq_mask_t mask;
	int err;

	err = sxok(sx126x_get_irq_status(radio, &mask));
	if (!err) err = sxok(sx126x_clear_irq_status(radio, mask));
	if (err) return err;
	radio->last_irq = mask;
	if (irq) *irq = mask;
	if (!(mask & SX126X_IRQ_RX_DONE)) return 0;
	err = sxok(sx126x_get_rx_buffer_status(radio, &buffer));
	if (!err && buffer.pld_len_in_bytes > sizeof(radio->last_rx)) err = -EOVERFLOW;
	if (!err) err = sxok(sx126x_read_buffer(radio, buffer.buffer_start_pointer, radio->last_rx, buffer.pld_len_in_bytes));
	if (!err) err = sxok(sx126x_get_lora_pkt_status(radio, &packet));
	if (err) return err;
	radio->last_rx_len = buffer.pld_len_in_bytes;
	radio->last_rssi_dbm = packet.rssi_pkt_in_dbm;
	radio->last_snr_db = packet.snr_pkt_in_db;
	return 0;
}

int radio_linux_cleanup(struct radio_linux *radio)
{
	struct radio_cleanup_ops ops = { standby_rc, switch_idle, idle_readback, reset_low };
	return radio_cleanup(&ops, radio, &radio->faulted);
}
