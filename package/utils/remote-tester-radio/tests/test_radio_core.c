/* SPDX-License-Identifier: GPL-2.0-only */
#include "radio_core.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

struct fake {
	int standby_result;
	int idle_result;
	int readback_result;
	unsigned int calls[4];
};

static int standby(void *context)
{
	struct fake *fake = context;
	fake->calls[0]++;
	return fake->standby_result;
}

static int idle(void *context)
{
	struct fake *fake = context;
	fake->calls[1]++;
	return fake->idle_result;
}

static int readback(void *context)
{
	struct fake *fake = context;
	fake->calls[2]++;
	return fake->readback_result;
}

static int reset(void *context)
{
	((struct fake *)context)->calls[3]++;
	return 0;
}

int main(void)
{
	struct radio_config config = { RADIO_DEFAULT_MHZ, 125, 7, 5, 0x1424, RADIO_DEFAULT_SPI_HZ, false };
	struct radio_scan_request scan = { 410, 490, 740 };
	struct fake fake = {};
	struct radio_cleanup_ops cleanup = { standby, idle, readback, reset };
	bool fault;

	assert(!radio_config_validate(&config));
	config.frequency_mhz = 409; assert(radio_config_validate(&config)); config.frequency_mhz = 433;
	config.bandwidth_khz = 126; assert(radio_config_validate(&config)); config.bandwidth_khz = 500;
	config.spreading_factor = 13; assert(radio_config_validate(&config)); config.spreading_factor = 12;
	config.coding_rate = 9; assert(radio_config_validate(&config)); config.coding_rate = 8;
	config.spi_hz = 16000001; assert(radio_config_validate(&config)); config.spi_hz = RADIO_DEFAULT_SPI_HZ;
	assert(!radio_scan_validate(&scan));
	scan.dwell_ms = 1000; assert(radio_scan_validate(&scan)); scan.dwell_ms = 50;
	scan.start_mhz = 490; scan.end_mhz = 410; assert(radio_scan_validate(&scan));
	assert(radio_scan_dwell_fits(1000, 2000, 1000));
	assert(!radio_scan_dwell_fits(1000, 1999, 1000));
	assert(!radio_scan_dwell_fits(2000, 2000, 1));
	assert(!radio_scan_dwell_fits(0, 2000, 1));
	assert(radio_ldro_required(11, 125));
	assert(radio_ldro_required(12, 125));
	assert(radio_ldro_required(12, 250));
	assert(!radio_ldro_required(11, 250));
	assert(!radio_ldro_required(12, 500));
	assert(!radio_tx_allowed(&config, true)); config.allow_tx_test = true;
	assert(radio_tx_allowed(&config, true)); assert(!radio_tx_allowed(&config, false));
	assert(strlen(RADIO_TX_PAYLOAD) == RADIO_TX_PAYLOAD_LEN);
	assert(radio_op_can_start(RADIO_OP_IDLE)); assert(!radio_op_can_start(RADIO_OP_SCAN));
	fault = false; assert(!radio_cleanup(&cleanup, &fake, &fault)); assert(!fault && fake.calls[3] == 0);
	fault = true; assert(!radio_cleanup(&cleanup, &fake, &fault)); assert(fault && fake.calls[3] == 0);
	fake.readback_result = -1; assert(radio_cleanup(&cleanup, &fake, &fault) == -1); assert(fault && fake.calls[3] == 1);
	puts("radio core tests: ok");
	return 0;
}
