/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef REMOTE_TESTER_RADIOLIB_BACKEND_H
#define REMOTE_TESTER_RADIOLIB_BACKEND_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct radio_config;
struct radio_linux;

#ifdef __cplusplus
extern "C" {
#endif

int radiolib_backend_create(struct radio_linux *radio);
void radiolib_backend_destroy(struct radio_linux *radio);
int radiolib_backend_configure(struct radio_linux *radio, const struct radio_config *config);
int radiolib_backend_set_frequency(struct radio_linux *radio, uint32_t frequency_mhz);
int radiolib_backend_start_receive(struct radio_linux *radio, uint8_t payload_len, bool continuous);
int radiolib_backend_start_transmit(struct radio_linux *radio, const uint8_t *data, size_t len);
int radiolib_backend_start_cad(struct radio_linux *radio);
int radiolib_backend_handle_irq(struct radio_linux *radio, uint16_t *irq);
int radiolib_backend_sample_rssi(struct radio_linux *radio, int16_t *rssi_dbm);
int radiolib_backend_diagnostics(struct radio_linux *radio, uint8_t *chip_mode,
	uint8_t *command_status, uint16_t *sync_word);
int radiolib_backend_standby_rc(struct radio_linux *radio);

#ifdef __cplusplus
}
#endif

#endif
