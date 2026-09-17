/* SPDX-License-Identifier: GPL-2.0-only */
#include "radio_core.h"
#include <errno.h>

int radio_config_validate(const struct radio_config *config)
{
	if (!config || config->frequency_mhz < 410 || config->frequency_mhz > 490 ||
	    (config->bandwidth_khz != 125 && config->bandwidth_khz != 250 && config->bandwidth_khz != 500) ||
	    config->spreading_factor < 7 || config->spreading_factor > 12 || config->coding_rate < 5 ||
	    config->coding_rate > 8 || config->sync_word > 0xffff || config->spi_hz == 0 || config->spi_hz > 16000000)
		return -EINVAL;
	return 0;
}

int radio_scan_validate(const struct radio_scan_request *request)
{
	uint32_t points;
	if (!request || request->start_mhz < 410 || request->end_mhz > 490 || request->start_mhz > request->end_mhz ||
	    request->dwell_ms < 50 || request->dwell_ms > 1000)
		return -EINVAL;
	points = request->end_mhz - request->start_mhz + 1;
	return points > 60000 / request->dwell_ms ? -EINVAL : 0;
}

bool radio_scan_dwell_fits(uint64_t now_ms, uint64_t deadline_ms, uint32_t dwell_ms)
{
	return now_ms && now_ms < deadline_ms && dwell_ms <= deadline_ms - now_ms;
}

bool radio_ldro_required(uint32_t spreading_factor, uint32_t bandwidth_khz)
{
	return (bandwidth_khz == 125 && spreading_factor >= 11) ||
		(bandwidth_khz == 250 && spreading_factor == 12);
}

bool radio_tx_allowed(const struct radio_config *config, bool antenna_confirmed)
{
	return config && config->allow_tx_test && antenna_confirmed;
}

bool radio_op_can_start(enum radio_op op)
{
	return op == RADIO_OP_IDLE;
}

int radio_cleanup(const struct radio_cleanup_ops *ops, void *ctx, bool *faulted)
{
	int standby, idle;
	bool fault_was_latched = faulted && *faulted;

	if (faulted)
		*faulted = true;
	int readback;
	if (!ops || !ops->standby_rc || !ops->switch_idle || !ops->idle_readback || !ops->reset_low)
		return -EINVAL;
	standby = ops->standby_rc(ctx);
	idle = ops->switch_idle(ctx);
	readback = idle ? idle : ops->idle_readback(ctx);
	if (standby || idle || readback) {
		(void)ops->reset_low(ctx);
		return standby ? standby : (idle ? idle : readback);
	}
	if (faulted && !fault_was_latched)
		*faulted = false;
	return 0;
}
