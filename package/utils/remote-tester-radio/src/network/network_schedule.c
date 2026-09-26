/* SPDX-License-Identifier: GPL-2.0-only */
#include "network.h"

#include <errno.h>
#include <string.h>

#define MAX_SCHEDULE_AIRTIME_US(downlink) \
	((NETWORK_FRAME_MS - (downlink) - NETWORK_CONTENTION_MS - \
	  (NETWORK_MAX_GRANTS + 1U) * NETWORK_GUARD_MS) * 1000U)

static uint32_t get_u32(const uint8_t *in)
{
	return (uint32_t)in[0] | ((uint32_t)in[1] << 8) |
		((uint32_t)in[2] << 16) | ((uint32_t)in[3] << 24);
}

static uint64_t get_u64(const uint8_t *in)
{
	return (uint64_t)get_u32(in) | ((uint64_t)get_u32(in + 4) << 32);
}

int network_scheduler_init(struct network_scheduler *scheduler, uint32_t airtime_budget_us,
	uint16_t downlink_ms)
{
	uint32_t safe_airtime_us;
	if (!scheduler || !airtime_budget_us || !downlink_ms ||
	    (uint32_t)downlink_ms + NETWORK_CONTENTION_MS +
	    (NETWORK_MAX_GRANTS + 1U) * NETWORK_GUARD_MS >= NETWORK_FRAME_MS)
		return -EINVAL;
	safe_airtime_us = MAX_SCHEDULE_AIRTIME_US(downlink_ms);
	if (airtime_budget_us > safe_airtime_us)
		airtime_budget_us = safe_airtime_us;
	scheduler->max_airtime_per_frame_us = (airtime_budget_us / 1000U) * 1000U;
	scheduler->downlink_ms = downlink_ms;
	return scheduler->max_airtime_per_frame_us ? 0 : -EINVAL;
}

int network_scheduler_build_grants(struct network_scheduler *scheduler, uint32_t frame_number,
	const struct network_demand demands[NETWORK_MAX_NODES],
	uint32_t minimum_packet_airtime_us, struct network_grant *grants,
	size_t grant_capacity, size_t *grant_count)
{
	uint32_t packets_remaining[NETWORK_MAX_NODES] = { 0 };
	uint32_t packet_airtime_us;
	uint32_t remaining_airtime_us;
	uint8_t next_node, i;
	size_t count = 0;
	uint64_t cursor_us, frame_cutoff_us;

	if (!scheduler || !demands || !grants || !grant_count ||
	    !minimum_packet_airtime_us)
		return -EINVAL;
	if (grant_capacity < NETWORK_MAX_GRANTS)
		return -ENOSPC;
	*grant_count = 0;
	if (minimum_packet_airtime_us > scheduler->max_airtime_per_frame_us)
		return -EMSGSIZE;
	/* Whole-ms timers can dispatch late; reserve explicit time for dispatch and PHY start. */
	packet_airtime_us = ((minimum_packet_airtime_us + 999U) / 1000U) * 1000U +
		NETWORK_TX_START_MARGIN_MS * 1000U;
	remaining_airtime_us = scheduler->max_airtime_per_frame_us;
	for (i = 0; i < NETWORK_MAX_NODES; i++) {
		if (!demands[i].joined || !demands[i].requested_airtime_us)
			continue;
		packets_remaining[i] = (uint32_t)(((uint64_t)demands[i].requested_airtime_us +
			minimum_packet_airtime_us - 1U) / minimum_packet_airtime_us);
	}

	/* Rotate the starting peer by frame and schedule only whole-packet windows. */
	next_node = (uint8_t)(frame_number % NETWORK_MAX_NODES);
	cursor_us = (uint64_t)scheduler->downlink_ms * 1000ULL;
	frame_cutoff_us = (NETWORK_FRAME_MS - NETWORK_CONTENTION_MS -
		NETWORK_GUARD_MS) * 1000ULL;
	while (count < NETWORK_MAX_GRANTS && remaining_airtime_us >= packet_airtime_us) {
		bool found = false;
		uint8_t node_index = next_node;
		for (i = 0; i < NETWORK_MAX_NODES; i++) {
			node_index = (uint8_t)((next_node + i) % NETWORK_MAX_NODES);
			if (packets_remaining[node_index]) {
				found = true;
				break;
			}
		}
		if (!found)
			break;
		cursor_us += NETWORK_GUARD_MS * 1000ULL;
		if (cursor_us + packet_airtime_us > frame_cutoff_us)
			break;
		grants[count].node_id = (uint8_t)(node_index + NETWORK_FIRST_NODE_ID);
		grants[count].start_offset_us = (uint32_t)cursor_us;
		grants[count].airtime_budget_us = packet_airtime_us;
		cursor_us += packet_airtime_us;
		remaining_airtime_us -= packet_airtime_us;
		packets_remaining[node_index]--;
		count++;
		next_node = (uint8_t)((node_index + 1U) % NETWORK_MAX_NODES);
	}
	*grant_count = count;
	return 0;
}

void network_node_init(struct network_node_link *node, uint32_t network_id,
	uint64_t node_boot_nonce, const uint8_t eui[8])
{
	if (!node || !eui)
		return;
	memset(node, 0, sizeof(*node));
	node->node_id = NETWORK_UNASSIGNED_NODE_ID;
	memcpy(node->eui, eui, sizeof(node->eui));
	node->network_id = network_id;
	node->node_boot_nonce = node_boot_nonce;
	node->state = NETWORK_NODE_UNJOINED;
}

int network_node_begin_join(struct network_node_link *node)
{
	uint8_t checked_eui[8];
	if (!node || !node->network_id || !node->node_boot_nonce)
		return -EINVAL;
	if (network_join_payload_encode(node->eui, checked_eui))
		return -EINVAL;
	node->node_id = NETWORK_UNASSIGNED_NODE_ID;
	node->state = NETWORK_NODE_JOINING;
	node->joined = false;
	node->controller_boot_nonce = 0;
	node->grant_count = 0;
	return 0;
}

int network_node_build_join(const struct network_node_link *node, uint32_t sequence,
	struct network_frame *frame)
{
	uint8_t checked_eui[8];
	if (!node || !frame || node->state != NETWORK_NODE_JOINING || !node->network_id ||
	    !node->node_boot_nonce)
		return -EINVAL;
	if (network_join_payload_encode(node->eui, checked_eui))
		return -EINVAL;
	memset(frame, 0, sizeof(*frame));
	frame->type = NETWORK_FRAME_JOIN;
	frame->source = NETWORK_UNASSIGNED_NODE_ID;
	frame->destination = NETWORK_CONTROLLER_ID;
	frame->sequence = sequence;
	frame->network_id = node->network_id;
	frame->source_boot_nonce = node->node_boot_nonce;
	frame->payload_length = sizeof(node->eui);
	memcpy(frame->payload, node->eui, sizeof(node->eui));
	return 0;
}

int network_node_observe_join_response(struct network_node_link *node,
	const struct network_frame *response)
{
	if (!node || !response || node->state != NETWORK_NODE_JOINING ||
	    response->type != NETWORK_FRAME_JOIN_RESPONSE ||
	    response->source != NETWORK_CONTROLLER_ID ||
	    response->destination != NETWORK_UNASSIGNED_NODE_ID ||
	    response->network_id != node->network_id || !response->controller_boot_nonce ||
	    response->source_boot_nonce != response->controller_boot_nonce ||
	    response->payload_length != 9 ||
	    response->payload[0] < NETWORK_FIRST_NODE_ID ||
	    response->payload[0] > NETWORK_MAX_ID ||
	    get_u64(response->payload + 1) != node->node_boot_nonce)
		return -EACCES;
	node->node_id = response->payload[0];
	node->controller_boot_nonce = response->controller_boot_nonce;
	node->joined = true;
	return 0;
}

int network_node_observe_beacon(struct network_node_link *node,
	const struct network_frame *frame, uint64_t frame_start_us)
{
	struct network_beacon beacon;
	if (!node || !frame || !node->joined || frame->type != NETWORK_FRAME_BEACON ||
	    frame->source != NETWORK_CONTROLLER_ID ||
	    (frame->destination != NETWORK_BROADCAST_ID && frame->destination != node->node_id) ||
	    frame->network_id != node->network_id ||
	    frame->controller_boot_nonce != node->controller_boot_nonce ||
	    frame->source_boot_nonce != node->controller_boot_nonce)
		return -EACCES;
	if (network_beacon_decode(frame->payload, frame->payload_length, &beacon))
		return -EBADMSG;
	if (node->state == NETWORK_NODE_SYNCED && beacon.frame_number == node->synced_frame)
		return -EALREADY;
	if (node->state == NETWORK_NODE_SYNCED &&
	    beacon.frame_number != node->synced_frame + 1U) {
		node->state = NETWORK_NODE_SYNC_LOST;
		node->joined = false;
		node->controller_boot_nonce = 0;
		node->grant_count = 0;
		return -ESTALE;
	}
	node->last_beacon_frame = beacon.frame_number;
	node->synced_frame = beacon.frame_number;
	node->frame_start_us = frame_start_us;
	node->grant_count = beacon.grant_count;
	memcpy(node->grants, beacon.grants, beacon.grant_count * sizeof(node->grants[0]));
	node->state = NETWORK_NODE_SYNCED;
	return 0;
}

bool network_node_check_sync(struct network_node_link *node, uint32_t current_frame_number)
{
	if (!node)
		return false;
	if (node->state == NETWORK_NODE_SYNCED && current_frame_number != node->synced_frame) {
		node->state = NETWORK_NODE_SYNC_LOST;
		node->joined = false;
		node->controller_boot_nonce = 0;
		node->grant_count = 0;
		return false;
	}
	return node->state == NETWORK_NODE_SYNCED;
}

bool network_node_tx_window(const struct network_node_link *node, uint32_t frame_number,
	uint64_t now_us, uint32_t packet_airtime_us)
{
	size_t i;
	if (!node || node->state != NETWORK_NODE_SYNCED || frame_number != node->synced_frame ||
	    frame_number != node->last_beacon_frame || !packet_airtime_us || now_us < node->frame_start_us)
		return false;
	for (i = 0; i < node->grant_count; i++) {
		const struct network_grant *grant = &node->grants[i];
		uint64_t start, end;
		if (grant->node_id != node->node_id)
			continue;
		start = node->frame_start_us + grant->start_offset_us;
		end = start + grant->airtime_budget_us;
		if (now_us >= start && now_us < end && packet_airtime_us <= end - now_us)
			return true;
	}
	return false;
}

uint32_t network_contention_backoff_ms(uint8_t attempt, uint32_t random_value,
	uint32_t base_slot_ms, uint32_t cap_ms)
{
	uint16_t exponent = (uint16_t)attempt + 3U;
	uint32_t slots;
	uint64_t delay;
	if (!base_slot_ms || !cap_ms)
		return 0;
	if (exponent > 8U)
		exponent = 8U;
	slots = 1U << exponent;
	delay = (uint64_t)(random_value % slots) * base_slot_ms;
	if (cap_ms > NETWORK_CONTENTION_MS)
		cap_ms = NETWORK_CONTENTION_MS;
	return delay > cap_ms ? cap_ms : (uint32_t)delay;
}

uint32_t network_contention_slot_time_ms(uint8_t spreading_factor,
	uint32_t bandwidth_khz, uint8_t cad_symbols)
{
	uint64_t symbol_us, symbols_x2, slot_us;
	if (spreading_factor < 7 || spreading_factor > 12 ||
	    (bandwidth_khz != 125 && bandwidth_khz != 250 && bandwidth_khz != 500))
		return 0;
	/* Adapt meshSlotTimeMs: (CAD symbols + 0.5) * symbol time + 7.6 ms. */
	symbols_x2 = (uint64_t)cad_symbols * 2U + 1U;
	if (symbols_x2 < 5U)
		symbols_x2 = 5U;
	symbol_us = (((uint64_t)1U << spreading_factor) * 1000U +
		bandwidth_khz - 1U) / bandwidth_khz;
	slot_us = (symbol_us * symbols_x2 + 1U) / 2U + 7600U;
	return (uint32_t)((slot_us + 999U) / 1000U);
}

bool network_contention_tx_allowed(bool in_contention_window, bool cad_clear,
	bool backoff_expired)
{
	return in_contention_window && cad_clear && backoff_expired;
}

bool network_retry_allowed(uint8_t retries_already_used)
{
	return retries_already_used < NETWORK_MAX_RETRIES;
}

/* The arithmetic follows LoRaMesher v1.0.0: per-subslot guard, evenly divided
 * usable window, and min(30 ms, 10% of slot) trailing guard. Only the timing
 * rule is adapted; this implementation contains no copied LoRaMesher source. */
int network_subslot_compute(uint32_t slot_duration_us, uint8_t subslot_count,
	uint32_t guard_us, uint16_t identifier, struct network_subslot_timing *timing)
{
	uint64_t total_guard, trailing_guard, available;
	uint32_t window;
	uint64_t tx_start;
	if (!timing || !slot_duration_us || !subslot_count)
		return -EINVAL;
	memset(timing, 0, sizeof(*timing));
	total_guard = (uint64_t)subslot_count * guard_us;
	if (total_guard >= slot_duration_us)
		return -ERANGE;
	trailing_guard = slot_duration_us / 10U;
	if (trailing_guard > 30000U)
		trailing_guard = 30000U;
	if (total_guard + trailing_guard >= slot_duration_us)
		trailing_guard = 0;
	available = slot_duration_us - total_guard - trailing_guard;
	window = (uint32_t)(available / subslot_count);
	if (!window)
		return -ERANGE;
	timing->assigned_subslot = (uint8_t)(identifier % subslot_count);
	timing->tx_window_us = window;
	if (guard_us > UINT32_MAX - window)
		return -ERANGE;
	timing->subslot_duration_us = guard_us + window;
	tx_start = (uint64_t)timing->assigned_subslot * timing->subslot_duration_us + guard_us;
	if (tx_start > UINT32_MAX)
		return -ERANGE;
	timing->tx_start_offset_us = (uint32_t)tx_start;
	return 0;
}
