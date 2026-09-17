/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef REMOTE_TESTER_RADIO_LINUX_H
#define REMOTE_TESTER_RADIO_LINUX_H

#include "radio_core.h"
#include <stdbool.h>
#include <stdint.h>

struct gpiod_chip;
struct gpiod_line;

struct radio_lines {
	const char *reset;
	const char *busy;
	const char *dio1;
	const char *txen;
	const char *rxen;
};

struct radio_linux {
	int spi_fd;
	uint32_t spi_hz;
	struct gpiod_chip *chip;
	struct gpiod_line *reset;
	struct gpiod_line *busy;
	struct gpiod_line *dio1;
	struct gpiod_line *txen;
	struct gpiod_line *rxen;
	uint8_t last_rx[240];
	uint8_t last_rx_len;
	int8_t last_rssi_dbm;
	int8_t last_snr_db;
	uint16_t last_irq;
	uint16_t last_sync_word;
	uint8_t last_chip_mode;
	uint8_t last_command_status;
	bool faulted;
	bool configured;
};

int radio_linux_open(struct radio_linux *radio, const char *spidev, const char *gpiochip,
	const struct radio_lines *lines, const struct radio_config *config);
void radio_linux_close(struct radio_linux *radio);
int radio_linux_configure(struct radio_linux *radio, const struct radio_config *config, uint8_t payload_len);
int radio_linux_probe(struct radio_linux *radio, const struct radio_config *config);
int radio_linux_set_frequency(struct radio_linux *radio, uint32_t frequency_mhz);
int radio_linux_start_receive(struct radio_linux *radio, uint8_t payload_len, bool continuous);
int radio_linux_start_tx_test(struct radio_linux *radio);
int radio_linux_sample_rssi(struct radio_linux *radio, int16_t *rssi_dbm);
int radio_linux_handle_irq(struct radio_linux *radio, uint16_t *irq);
int radio_linux_cleanup(struct radio_linux *radio);

#endif
