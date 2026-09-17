/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef REMOTE_TESTER_RADIO_CORE_H
#define REMOTE_TESTER_RADIO_CORE_H

#include <stdbool.h>
#include <stdint.h>

#define RADIO_DEFAULT_MHZ 433U
#define RADIO_DEFAULT_SPI_HZ 2000000U
#define RADIO_TX_PAYLOAD "RT-MT7628-TX-TEST-0000001"
#define RADIO_TX_PAYLOAD_LEN 25U

enum radio_op {
	RADIO_OP_IDLE,
	RADIO_OP_SCAN,
	RADIO_OP_RECEIVE,
	RADIO_OP_TX,
};

struct radio_config {
	uint32_t frequency_mhz;
	uint32_t bandwidth_khz;
	uint32_t spreading_factor;
	uint32_t coding_rate;
	uint32_t sync_word;
	uint32_t spi_hz;
	bool allow_tx_test;
};

struct radio_scan_request {
	uint32_t start_mhz;
	uint32_t end_mhz;
	uint32_t dwell_ms;
};

struct radio_cleanup_ops {
	int (*standby_rc)(void *ctx);
	int (*switch_idle)(void *ctx);
	int (*idle_readback)(void *ctx);
	int (*reset_low)(void *ctx);
};

int radio_config_validate(const struct radio_config *config);
int radio_scan_validate(const struct radio_scan_request *request);
bool radio_scan_dwell_fits(uint64_t now_ms, uint64_t deadline_ms, uint32_t dwell_ms);
bool radio_ldro_required(uint32_t spreading_factor, uint32_t bandwidth_khz);
bool radio_tx_allowed(const struct radio_config *config, bool antenna_confirmed);
bool radio_op_can_start(enum radio_op op);
int radio_cleanup(const struct radio_cleanup_ops *ops, void *ctx, bool *faulted);

#endif
