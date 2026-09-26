/* SPDX-License-Identifier: GPL-2.0-only */
#include "network.h"

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

static const uint32_t test_network_id = 0x7628a11U;

static void fill_bytes(uint8_t *bytes, size_t length, uint8_t seed)
{
	size_t i;
	for (i = 0; i < length; i++)
		bytes[i] = (uint8_t)(seed + (uint8_t)(i * 37U));
}

static size_t make_beacon_frame(uint32_t frame_number, uint64_t controller_nonce,
	uint8_t destination, const struct network_beacon *beacon, const uint8_t *key,
	struct network_frame *frame, uint8_t wire[NETWORK_FRAME_MAX_BYTES])
{
	size_t payload_length, wire_length;
	memset(frame, 0, sizeof(*frame));
	frame->type = NETWORK_FRAME_BEACON;
	frame->source = NETWORK_CONTROLLER_ID;
	frame->destination = destination;
	frame->sequence = frame_number + 20U;
	frame->network_id = test_network_id;
	frame->source_boot_nonce = controller_nonce;
	frame->controller_boot_nonce = controller_nonce;
	assert(network_beacon_encode(beacon, frame->payload, sizeof(frame->payload), &payload_length) == 0);
	frame->payload_length = (uint16_t)payload_length;
	assert(network_frame_encode(frame, key, wire, NETWORK_FRAME_MAX_BYTES, &wire_length) == 0);
	return wire_length;
}

static void test_join_auth_and_replay(void)
{
	uint8_t key[NETWORK_KEY_BYTES], wrong_key[NETWORK_KEY_BYTES], eui[8] = { 0x02, 1, 2, 3, 4, 5, 6, 7 };
	uint8_t registry_keys[NETWORK_MAX_NODES][NETWORK_KEY_BYTES];
	uint8_t wire[NETWORK_FRAME_MAX_BYTES], payload[9];
	struct network_node_link node, rebooted;
	struct network_frame join, peeked, decoded, response, beacon_frame;
	struct network_frame node_data;
	struct network_replay_table controller_replay, node_replay, reboot_replay;
	struct network_replay_table bad_replay, join_replay, candidate_replay;
	struct network_beacon beacon;
	size_t wire_length;
	uint64_t controller_nonce = 0xaabbccdd10203040ULL;
	uint64_t new_node_nonce = 0x7711223344556677ULL;

	fill_bytes(key, sizeof(key), 0x35);
	fill_bytes(wrong_key, sizeof(wrong_key), 0x91);
	network_node_init(&node, test_network_id, 0x1122334455667788ULL, eui);
	assert(network_node_begin_join(&node) == 0);
	assert(network_node_build_join(&node, 1, &join) == 0);
	assert(join.source == NETWORK_UNASSIGNED_NODE_ID && join.destination == NETWORK_CONTROLLER_ID);
	assert(network_frame_encode(&join, key, wire, sizeof(wire), &wire_length) == 0);
	assert(wire_length <= NETWORK_FRAME_MAX_BYTES);
	assert(network_frame_peek(wire, wire_length, &peeked) == 0);
	assert(peeked.source == NETWORK_UNASSIGNED_NODE_ID && peeked.payload_length == sizeof(eui));
	assert(memcmp(peeked.payload, eui, sizeof(eui)) == 0);
	network_replay_init(&bad_replay, NETWORK_CONTROLLER_ID, test_network_id,
		controller_nonce, controller_nonce);
	wire[NETWORK_FRAME_HEADER_BYTES] ^= 1U;
	assert(network_frame_decode(wire, wire_length, key, &bad_replay, &decoded) == -EACCES);
	wire[NETWORK_FRAME_HEADER_BYTES] ^= 1U;
	network_replay_init(&controller_replay, NETWORK_CONTROLLER_ID, test_network_id,
		controller_nonce, controller_nonce);
	assert(controller_replay.initialized);
	for (size_t candidate = 0; candidate < NETWORK_MAX_NODES; candidate++)
		fill_bytes(registry_keys[candidate], NETWORK_KEY_BYTES, (uint8_t)(candidate + 1U));
	memcpy(registry_keys[NETWORK_MAX_NODES - 1U], key, NETWORK_KEY_BYTES);
	for (size_t candidate = 0; candidate < NETWORK_MAX_NODES - 1U; candidate++)
		assert(network_frame_decode(wire, wire_length, registry_keys[candidate],
			&controller_replay, &decoded) == -EACCES);
	assert(network_frame_decode(wire, wire_length, registry_keys[NETWORK_MAX_NODES - 1U],
		&controller_replay, &decoded) == 0);
	assert(decoded.source_boot_nonce == join.source_boot_nonce);
	network_replay_init(&join_replay, NETWORK_CONTROLLER_ID, test_network_id,
		controller_nonce, controller_nonce);
	assert(network_frame_decode(wire, wire_length, key, &join_replay, &decoded) == 0);
	join.source_boot_nonce = new_node_nonce;
	join.sequence = 2;
	assert(network_frame_encode(&join, key, wire, sizeof(wire), &wire_length) == 0);
	assert(network_frame_decode(wire, wire_length, key, &join_replay, &decoded) == 0);
	join.source_boot_nonce = 0x1122334455667788ULL;
	join.sequence = 100;
	assert(network_frame_encode(&join, key, wire, sizeof(wire), &wire_length) == 0);
	assert(network_frame_decode(wire, wire_length, key, &join_replay, &decoded) == -ESTALE);
	join.source_boot_nonce = 0x1122334455667788ULL;
	join.sequence = 1;
	assert(network_frame_encode(&join, key, wire, sizeof(wire), &wire_length) == 0);
	assert(network_frame_decode(wire, wire_length, key, &controller_replay, &decoded) == -EALREADY);
	assert(network_frame_decode(wire, wire_length, wrong_key, &controller_replay, &decoded) == -EACCES);
	assert(network_replay_bind_node(&controller_replay, 3, join.source_boot_nonce,
		join.sequence) == 0);
	memset(&node_data, 0, sizeof(node_data));
	node_data.type = NETWORK_FRAME_DATA;
	node_data.source = 3;
	node_data.destination = NETWORK_CONTROLLER_ID;
	node_data.sequence = 2;
	node_data.network_id = test_network_id;
	node_data.source_boot_nonce = join.source_boot_nonce;
	node_data.controller_boot_nonce = controller_nonce;
	node_data.payload_length = 1;
	node_data.payload[0] = 0x5a;
	assert(network_frame_encode(&node_data, key, wire, sizeof(wire), &wire_length) == 0);
	assert(network_frame_decode(wire, wire_length, key, &controller_replay, &decoded) == 0);
	assert(network_replay_bind_node(&controller_replay, 3, new_node_nonce, 1) == 0);
	node_data.source_boot_nonce = join.source_boot_nonce;
	node_data.sequence = 100;
	assert(network_frame_encode(&node_data, key, wire, sizeof(wire), &wire_length) == 0);
	assert(network_frame_decode(wire, wire_length, key, &controller_replay, &decoded) == -ESTALE);
	node_data.source_boot_nonce = new_node_nonce;
	node_data.sequence = 2;
	assert(network_frame_encode(&node_data, key, wire, sizeof(wire), &wire_length) == 0);
	assert(network_frame_decode(wire, wire_length, key, &controller_replay, &decoded) == 0);

	assert(network_join_response_payload_encode(3, node.node_boot_nonce, payload) == 0);
	memset(&response, 0, sizeof(response));
	response.type = NETWORK_FRAME_JOIN_RESPONSE;
	response.source = NETWORK_CONTROLLER_ID;
	response.destination = NETWORK_UNASSIGNED_NODE_ID;
	response.sequence = 1;
	response.network_id = test_network_id;
	response.source_boot_nonce = controller_nonce;
	response.controller_boot_nonce = controller_nonce;
	response.payload_length = sizeof(payload);
	memcpy(response.payload, payload, sizeof(payload));
	assert(network_frame_encode(&response, key, wire, sizeof(wire), &wire_length) == 0);
	network_replay_init(&node_replay, NETWORK_UNASSIGNED_NODE_ID, test_network_id,
		node.node_boot_nonce, 0);
	assert(network_frame_decode(wire, wire_length, key, &node_replay, &decoded) == 0);
	assert(node_replay.local_id == 3 && node_replay.controller_boot_nonce == controller_nonce);
	assert(network_node_observe_join_response(&node, &decoded) == 0);
	assert(node.node_id == 3 && node.joined);

	memset(&beacon, 0, sizeof(beacon));
	beacon.frame_number = 10;
	beacon.contention_ms = NETWORK_CONTENTION_MS;
	beacon.downlink_ms = NETWORK_DEFAULT_DOWNLINK_MS;
	beacon.grant_count = 1;
	beacon.grants[0].node_id = 3;
	beacon.grants[0].start_offset_us = 250000;
	beacon.grants[0].airtime_budget_us = 100000;
	wire_length = make_beacon_frame(10, controller_nonce, 3, &beacon, key,
		&beacon_frame, wire);
	assert(network_frame_decode(wire, wire_length, key, &node_replay, &decoded) == 0);
	assert(network_node_observe_beacon(&node, &decoded, 1000000) == 0);
	assert(node.grant_count == 1 && node.synced_frame == 10);
	assert(network_node_tx_window(&node, 10, 1250000, 100000));
	assert(!network_node_tx_window(&node, 10, 1250000, 100001));
	assert(!network_node_tx_window(&node, 11, 1250000, 100));
	assert(!network_node_check_sync(&node, 11));
	assert(node.state == NETWORK_NODE_SYNC_LOST && node.grant_count == 0 && !node.joined);

	/* A fresh node boot nonce cannot accept a captured prior JOIN_RESPONSE/beacon. */
	network_node_init(&rebooted, test_network_id, new_node_nonce, eui);
	assert(network_node_begin_join(&rebooted) == 0);
	network_replay_init(&reboot_replay, NETWORK_UNASSIGNED_NODE_ID, test_network_id,
		new_node_nonce, 0);
	assert(network_frame_decode(wire, wire_length, key, &reboot_replay, &decoded) == -ESTALE);
	assert(network_join_response_payload_encode(4, node.node_boot_nonce, payload) == 0);
	response.sequence = 2;
	response.payload[0] = payload[0];
	memcpy(response.payload + 1, payload + 1, 8);
	assert(network_frame_encode(&response, key, wire, sizeof(wire), &wire_length) == 0);
	assert(network_frame_decode(wire, wire_length, key, &reboot_replay, &decoded) == -EACCES);
	assert(network_join_response_payload_encode(4, new_node_nonce, payload) == 0);
	response.source_boot_nonce = controller_nonce + 1;
	response.controller_boot_nonce = controller_nonce + 1;
	memcpy(response.payload, payload, sizeof(payload));
	assert(network_frame_encode(&response, key, wire, sizeof(wire), &wire_length) == 0);
	assert(network_frame_decode(wire, wire_length, key, &reboot_replay, &decoded) == 0);
	assert(network_node_observe_join_response(&rebooted, &decoded) == 0);
	assert(rebooted.node_id == 4);
	wire_length = make_beacon_frame(10, controller_nonce, rebooted.node_id, &beacon, key,
		&beacon_frame, wire);
	assert(network_frame_decode(wire, wire_length, key, &reboot_replay, &decoded) == -ESTALE);

	/* Once a node has learned the new controller nonce, old signed responses are stale. */
	assert(network_node_begin_join(&node) == 0);
	assert(network_replay_begin_join(&node_replay) == 0);
	assert(network_join_response_payload_encode(3, node.node_boot_nonce, payload) == 0);
	memcpy(response.payload, payload, sizeof(payload));
	response.sequence = 1;
	response.source_boot_nonce = controller_nonce + 2;
	response.controller_boot_nonce = controller_nonce + 2;
	assert(network_frame_encode(&response, key, wire, sizeof(wire), &wire_length) == 0);
	assert(network_frame_decode(wire, wire_length, key, &node_replay, &decoded) == 0);
	assert(network_node_observe_join_response(&node, &decoded) == 0);
	assert(network_replay_init_successor(&candidate_replay, &node_replay,
		NETWORK_UNASSIGNED_NODE_ID, test_network_id, node.node_boot_nonce,
		controller_nonce) == -ESTALE);
	assert(network_replay_init_successor(&candidate_replay, &node_replay,
		NETWORK_UNASSIGNED_NODE_ID, test_network_id, node.node_boot_nonce,
		controller_nonce + 3U) == 0);
	assert(candidate_replay.previous_controller_boot_nonces[0] == controller_nonce + 2U);
	assert(candidate_replay.previous_controller_boot_nonces[1] == controller_nonce);
	wire_length = make_beacon_frame(11, controller_nonce, node.node_id, &beacon, key,
		&beacon_frame, wire);
	assert(network_frame_decode(wire, wire_length, key, &node_replay, &decoded) == -ESTALE);
	assert(network_frame_decode(wire, wire_length, key, &candidate_replay, &decoded) == -ESTALE);
	response.sequence = 100;
	response.source_boot_nonce = controller_nonce;
	response.controller_boot_nonce = controller_nonce;
	assert(network_frame_encode(&response, key, wire, sizeof(wire), &wire_length) == 0);
	assert(network_frame_decode(wire, wire_length, key, &node_replay, &decoded) == -ESTALE);
}

static void test_scheduler_and_beacon(void)
{
	struct network_scheduler scheduler;
	struct network_demand demand[NETWORK_MAX_NODES] = { 0 };
	struct network_grant grants[NETWORK_MAX_GRANTS];
	struct network_beacon beacon, decoded;
	struct network_node_link node;
	struct network_frame frame, join_response;
	uint8_t payload[NETWORK_FRAME_MAX_PAYLOAD];
	uint8_t node_eui[8] = { 0x02, 9, 8, 7, 6, 5, 4, 3 };
	uint8_t join_payload[9];
	uint8_t command_key[NETWORK_KEY_BYTES], wrong_command_key[NETWORK_KEY_BYTES];
	size_t count, payload_length, i;
	uint32_t per_node[NETWORK_MAX_NODES] = { 0 };
	assert(network_scheduler_init(&scheduler, 4300000, NETWORK_DEFAULT_DOWNLINK_MS) == 0);
	assert(scheduler.max_airtime_per_frame_us == 1210000);
	assert(network_scheduler_init(&scheduler, 3450000, NETWORK_DEFAULT_DOWNLINK_MS) == 0);
	for (i = 0; i < NETWORK_MAX_NODES; i++) {
		demand[i].joined = true;
		demand[i].requested_airtime_us = 4000000;
	}
	assert(network_scheduler_build_grants(&scheduler, 7, demand, 100000, grants,
		NETWORK_MAX_GRANTS, &count) == 0);
	assert(count == 11U);
	for (i = 0; i < count; i++) {
		uint64_t end = (uint64_t)grants[i].start_offset_us + grants[i].airtime_budget_us;
		assert(grants[i].node_id >= 1 && grants[i].node_id <= 8);
		assert(grants[i].airtime_budget_us ==
			(100U + NETWORK_TX_START_MARGIN_MS) * 1000U);
		assert(grants[i].start_offset_us >=
			((uint32_t)NETWORK_DEFAULT_DOWNLINK_MS + NETWORK_GUARD_MS) * 1000U);
		assert(end <= (NETWORK_FRAME_MS - NETWORK_CONTENTION_MS -
			NETWORK_GUARD_MS) * 1000U);
		if (i)
			assert(grants[i].start_offset_us >=
				(uint64_t)grants[i - 1].start_offset_us + grants[i - 1].airtime_budget_us +
				(uint64_t)NETWORK_GUARD_MS * 1000U);
		per_node[grants[i].node_id - 1] += grants[i].airtime_budget_us;
	}
	for (i = 0; i < NETWORK_MAX_NODES; i++)
		assert(per_node[i] == (i == 0U || i == 1U || i == 7U ?
			204000U : 102000U));
	assert(network_scheduler_build_grants(&scheduler, 8, demand, 100000, grants,
		NETWORK_MAX_GRANTS - 1U, &count) == -ENOSPC);

	memset(&beacon, 0, sizeof(beacon));
	beacon.frame_number = 7;
	beacon.contention_ms = NETWORK_CONTENTION_MS;
	beacon.downlink_ms = NETWORK_DEFAULT_DOWNLINK_MS;
	beacon.grant_count = (uint8_t)count;
	/* Rebuild into the full grant array after the short-capacity failure. */
	assert(network_scheduler_build_grants(&scheduler, 7, demand, 100000, beacon.grants,
		NETWORK_MAX_GRANTS, &count) == 0);
	beacon.grant_count = (uint8_t)count;
	for (i = 0; i < NETWORK_MAX_ACK_ENTRIES; i++) {
		beacon.acknowledgements[i].node_id = (uint8_t)(i + 1U);
		beacon.acknowledgements[i].stream_id = 0x12340000U + (uint32_t)i;
		beacon.acknowledgements[i].block_id = (uint16_t)(200 + i);
		beacon.acknowledgements[i].received_bitmap = 0x80000001U ^ (uint32_t)i;
	}
	beacon.acknowledgement_count = NETWORK_MAX_ACK_ENTRIES;
	assert(network_beacon_encode(&beacon, payload, sizeof(payload), &payload_length) == 0);
	assert(payload_length <= NETWORK_FRAME_MAX_PAYLOAD);
	assert(network_beacon_decode(payload, payload_length, &decoded) == 0);
	assert(decoded.grant_count == 11U);
	assert(decoded.acknowledgement_count == NETWORK_MAX_ACK_ENTRIES);
	assert(decoded.grants[0].node_id == decoded.grants[8].node_id);
	assert(decoded.acknowledgements[7].received_bitmap == beacon.acknowledgements[7].received_bitmap);
	network_node_init(&node, test_network_id, 0x445566778899aabbULL, node_eui);
	assert(network_node_begin_join(&node) == 0);
	memset(&join_response, 0, sizeof(join_response));
	assert(network_join_response_payload_encode(beacon.grants[0].node_id,
		node.node_boot_nonce, join_payload) == 0);
	join_response.type = NETWORK_FRAME_JOIN_RESPONSE;
	join_response.source = NETWORK_CONTROLLER_ID;
	join_response.destination = NETWORK_UNASSIGNED_NODE_ID;
	join_response.network_id = test_network_id;
	join_response.source_boot_nonce = 0xabcdef1020304050ULL;
	join_response.controller_boot_nonce = join_response.source_boot_nonce;
	join_response.payload_length = sizeof(join_payload);
	memcpy(join_response.payload, join_payload, sizeof(join_payload));
	assert(network_node_observe_join_response(&node, &join_response) == 0);
	memset(&frame, 0, sizeof(frame));
	frame.type = NETWORK_FRAME_BEACON;
	frame.source = NETWORK_CONTROLLER_ID;
	frame.destination = node.node_id;
	frame.network_id = test_network_id;
	frame.source_boot_nonce = join_response.source_boot_nonce;
	frame.controller_boot_nonce = join_response.controller_boot_nonce;
	frame.payload_length = (uint16_t)payload_length;
	memcpy(frame.payload, payload, payload_length);
	assert(network_node_observe_beacon(&node, &frame, 1000000) == 0);
	assert(node.grant_count == 11U);
	assert(network_node_tx_window(&node, beacon.frame_number,
		1000000ULL + beacon.grants[8].start_offset_us, 1000));
	fill_bytes(command_key, sizeof(command_key), 0x61);
	fill_bytes(wrong_command_key, sizeof(wrong_command_key), 0x62);
	beacon.has_command = true;
	beacon.command.target_node_id = beacon.grants[0].node_id;
	beacon.command.sequence = 0x1234;
	beacon.command.length = 2;
	beacon.command.bytes[0] = 0x31;
	beacon.command.bytes[1] = 0x07;
	assert(network_beacon_command_sign(&beacon.command, test_network_id,
		join_response.controller_boot_nonce, beacon.frame_number, command_key,
		beacon.command.tag) == 0);
	assert(network_beacon_encode(&beacon, payload, sizeof(payload), &payload_length) == 0);
	assert(payload_length <= NETWORK_FRAME_MAX_PAYLOAD);
	assert(network_beacon_decode(payload, payload_length, &decoded) == 0 && decoded.has_command);
	assert(network_beacon_command_verify(&decoded, test_network_id,
		join_response.controller_boot_nonce, command_key) == 0);
	assert(network_beacon_command_verify(&decoded, test_network_id,
		join_response.controller_boot_nonce, wrong_command_key) == -EACCES);
	decoded.frame_number++;
	assert(network_beacon_command_verify(&decoded, test_network_id,
		join_response.controller_boot_nonce, command_key) == -EACCES);
	beacon.command.length = NETWORK_BEACON_COMMAND_MAX_BYTES;
	assert(network_beacon_command_sign(&beacon.command, test_network_id,
		join_response.controller_boot_nonce, beacon.frame_number, command_key,
		beacon.command.tag) == 0);
	assert(network_beacon_encode(&beacon, payload, sizeof(payload), &payload_length) == -EMSGSIZE);
	beacon.has_command = false;
	assert(network_beacon_encode(&beacon, payload, sizeof(payload), &payload_length) == 0);
	assert(network_beacon_decode(payload, payload_length - 1U, &decoded) == -EBADMSG);

	memset(demand, 0, sizeof(demand));
	demand[0].joined = true;
	demand[0].requested_airtime_us = 500000;
	assert(network_scheduler_build_grants(&scheduler, 1, demand, 250000, grants,
		NETWORK_MAX_GRANTS, &count) == 0);
	assert(count == 2 && grants[0].node_id == 1 && grants[1].node_id == 1);
	assert(grants[0].airtime_budget_us == 252000 && grants[1].airtime_budget_us == 252000);
}

static void test_scheduler_one_and_three_nodes(void)
{
	struct network_scheduler scheduler;
	struct network_demand demand[NETWORK_MAX_NODES] = { 0 };
	struct network_grant grants[NETWORK_MAX_GRANTS];
	size_t count, i;
	uint32_t sum[3] = { 0 };
	assert(network_scheduler_init(&scheduler, 3450000, NETWORK_DEFAULT_DOWNLINK_MS) == 0);
	demand[0].joined = true;
	demand[0].requested_airtime_us = 300000;
	assert(network_scheduler_build_grants(&scheduler, 1, demand, 100000, grants,
		NETWORK_MAX_GRANTS, &count) == 0);
	assert(count == 3);
	for (i = 0; i < count; i++)
		assert(grants[i].airtime_budget_us == 102000U);
	memset(demand, 0, sizeof(demand));
	for (i = 0; i < 3; i++) {
		demand[i].joined = true;
		demand[i].requested_airtime_us = 3000000;
	}
	assert(network_scheduler_build_grants(&scheduler, 2, demand, 100000, grants,
		NETWORK_MAX_GRANTS, &count) == 0);
	assert(count == 11U);
	for (i = 0; i < count; i++)
		sum[grants[i].node_id - 1] += grants[i].airtime_budget_us;
	assert(sum[0] == 408000U);
	assert(sum[1] == 306000U);
	assert(sum[2] == 408000U);
}

static uint32_t test_sf7_data_toa_us(uint32_t bandwidth_khz)
{
	const uint32_t spreading_factor = 7;
	const uint32_t coding_rate = 5;
	uint64_t coded_bits = 8ULL * NETWORK_DATA_FRAME_MAX_BYTES -
		4ULL * spreading_factor + 28U + 16U;
	uint64_t denominator = 4U * spreading_factor;
	uint64_t payload_symbols = 8U +
		(coded_bits + denominator - 1U) / denominator * coding_rate;
	uint64_t symbol_x4 = 4U * (8U + payload_symbols) + 17U;
	uint64_t numerator = (1ULL << spreading_factor) * 1000000ULL * symbol_x4;
	uint64_t divisor = (uint64_t)bandwidth_khz * 1000U * 4U;
	return (uint32_t)((numerator + divisor - 1U) / divisor);
}

static void test_packet_sized_scheduler(void)
{
	struct network_scheduler scheduler;
	struct network_demand demands[NETWORK_MAX_NODES] = { 0 };
	struct network_grant grants[NETWORK_MAX_GRANTS];
	uint32_t served_over_eight_frames[NETWORK_MAX_NODES] = { 0 };
	uint32_t toa_125 = test_sf7_data_toa_us(125);
	uint32_t toa_500 = test_sf7_data_toa_us(500);
	size_t count, i;
	assert(NETWORK_DATA_FRAME_MAX_BYTES == 222U);
	assert(toa_125 == 348416U && toa_500 == 87104U);
	assert(network_scheduler_init(&scheduler, 4300000,
		NETWORK_DEFAULT_DOWNLINK_MS) == 0);
	for (i = 0; i < NETWORK_MAX_NODES; i++) {
		demands[i].joined = true;
		demands[i].requested_airtime_us = toa_125 * 12U;
	}
	for (uint32_t frame = 0; frame < NETWORK_MAX_NODES; frame++) {
		uint32_t served_this_frame[NETWORK_MAX_NODES] = { 0 };
		uint32_t total_airtime_us = 0;
		assert(network_scheduler_build_grants(&scheduler, frame, demands, toa_125,
			grants, NETWORK_MAX_GRANTS, &count) == 0);
		assert(count == 3);
		for (i = 0; i < count; i++) {
			uint64_t end = (uint64_t)grants[i].start_offset_us +
				grants[i].airtime_budget_us;
			assert(grants[i].node_id >= NETWORK_FIRST_NODE_ID &&
				grants[i].node_id <= NETWORK_MAX_ID);
			assert(grants[i].airtime_budget_us >= toa_125);
			assert(grants[i].airtime_budget_us ==
				(349U + NETWORK_TX_START_MARGIN_MS) * 1000U);
			assert(end <= (NETWORK_FRAME_MS - NETWORK_CONTENTION_MS -
				NETWORK_GUARD_MS) * 1000U);
			if (i)
				assert(grants[i].start_offset_us >=
					(uint64_t)grants[i - 1].start_offset_us +
					grants[i - 1].airtime_budget_us +
					(uint64_t)NETWORK_GUARD_MS * 1000U);
			served_this_frame[grants[i].node_id - 1U]++;
			total_airtime_us += grants[i].airtime_budget_us;
		}
		assert(total_airtime_us <= scheduler.max_airtime_per_frame_us);
		for (i = 0; i < NETWORK_MAX_NODES; i++)
			served_over_eight_frames[i] += served_this_frame[i];
	}
	for (i = 0; i < NETWORK_MAX_NODES; i++)
		assert(served_over_eight_frames[i] == 3);
	assert(network_scheduler_build_grants(&scheduler, 9, demands,
		scheduler.max_airtime_per_frame_us + 1U, grants,
		NETWORK_MAX_GRANTS, &count) == -EMSGSIZE);

	assert(network_scheduler_init(&scheduler, 4300000,
		NETWORK_DEFAULT_DOWNLINK_MS) == 0);
	for (i = 0; i < NETWORK_MAX_NODES; i++)
		demands[i].requested_airtime_us = toa_500 * 20U;
	assert(network_scheduler_build_grants(&scheduler, 0, demands, toa_500,
		grants, NETWORK_MAX_GRANTS, &count) == 0);
	assert(count == 13U);
	memset(served_over_eight_frames, 0, sizeof(served_over_eight_frames));
	for (i = 0; i < count; i++) {
		assert(grants[i].airtime_budget_us >= toa_500);
		assert(grants[i].airtime_budget_us ==
			(88U + NETWORK_TX_START_MARGIN_MS) * 1000U);
		served_over_eight_frames[grants[i].node_id - 1U]++;
	}
	for (i = 0; i < NETWORK_MAX_NODES; i++)
		assert(served_over_eight_frames[i] == (i < 5U ? 2U : 1U));
}

static void test_delayed_full_size_data_grant(void)
{
	struct network_scheduler scheduler;
	struct network_demand demands[NETWORK_MAX_NODES] = { 0 };
	struct network_grant grants[NETWORK_MAX_GRANTS];
	struct network_node_link node = { 0 };
	const uint32_t frame_number = 9U;
	const uint64_t frame_start_us = 1000000ULL;
	uint32_t toa_us = test_sf7_data_toa_us(500);
	size_t count;

	assert(toa_us == 87104U);
	assert(network_scheduler_init(&scheduler, 1210000U,
		NETWORK_DEFAULT_DOWNLINK_MS) == 0);
	demands[0].joined = true;
	demands[0].requested_airtime_us = toa_us;
	assert(network_scheduler_build_grants(&scheduler, frame_number, demands,
		toa_us, grants, NETWORK_MAX_GRANTS, &count) == 0);
	assert(count == 1U && grants[0].node_id == NETWORK_FIRST_NODE_ID);
	assert(grants[0].airtime_budget_us ==
		(88U + NETWORK_TX_START_MARGIN_MS) * 1000U);

	node.node_id = NETWORK_FIRST_NODE_ID;
	node.state = NETWORK_NODE_SYNCED;
	node.joined = true;
	node.synced_frame = node.last_beacon_frame = frame_number;
	node.frame_start_us = frame_start_us;
	node.grants[0] = grants[0];
	node.grant_count = (uint8_t)count;
	/* The full-size DATA grant survives 1.5 ms of timer lateness plus PHY start. */
	assert(network_node_tx_window(&node, frame_number,
		frame_start_us + grants[0].start_offset_us + 1500U, toa_us));
	assert(!network_node_tx_window(&node, frame_number,
		frame_start_us + grants[0].start_offset_us + 2900U, toa_us));
}

static void test_timing_and_backoff(void)
{
	struct network_subslot_timing timing;
	assert(network_contention_slot_time_ms(7, 125, 2) == 11);
	assert(network_contention_slot_time_ms(6, 100, 2) == 0);
	assert(network_contention_backoff_ms(0, 7, 11, 500) == 77);
	assert(network_contention_backoff_ms(5, 255, 11, 500) == NETWORK_CONTENTION_MS);
	assert(network_contention_tx_allowed(true, true, true));
	assert(!network_contention_tx_allowed(false, true, true));
	assert(!network_contention_tx_allowed(true, false, true));
	assert(!network_contention_tx_allowed(true, true, false));
	assert(network_retry_allowed(0) && network_retry_allowed(4));
	assert(!network_retry_allowed(5));
	assert(network_subslot_compute(500000, 8, 50000, 3, &timing) == 0);
	assert(timing.assigned_subslot == 3 && timing.tx_window_us == 8750);
	assert(timing.tx_start_offset_us == 226250);
	assert(network_subslot_compute(400000, 8, 50000, 3, &timing) == -ERANGE);
}

static void make_random_data(uint8_t *data, size_t length)
{
	uint32_t state = 0x614e2b39U;
	size_t i;
	for (i = 0; i < length; i++) {
		state ^= state << 13;
		state ^= state >> 17;
		state ^= state << 5;
		data[i] = (uint8_t)(state >> 24);
	}
}

static void test_queue(void)
{
	uint8_t storage[64], first[40], second[10], output[64], destination;
	struct network_queue queue;
	size_t length;
	fill_bytes(first, sizeof(first), 1);
	fill_bytes(second, sizeof(second), 90);
	assert(network_queue_init(&queue, storage, sizeof(storage)) == 0);
	assert(network_queue_push(&queue, 1, first, sizeof(first)) == 0);
	assert(network_queue_push(&queue, 1, second, sizeof(second)) == 0);
	assert(network_queue_demand_bytes(&queue, 1) == sizeof(first) + sizeof(second));
	assert(network_queue_push(&queue, 3, second, sizeof(second)) == -ENOSPC);
	assert(network_queue_peek(&queue, &destination, output, 1, &length) == -ENOSPC);
	assert(length == sizeof(first));
	assert(network_queue_peek(&queue, &destination, output, sizeof(output), &length) == 0);
	assert(destination == 1 && length == sizeof(first) && !memcmp(first, output, length));
	assert(network_queue_peek(&queue, &destination, output, sizeof(output), &length) == 0);
	assert(destination == 1 && length == sizeof(first) && !memcmp(first, output, length));
	assert(network_queue_drop_front(&queue, &destination, &length) == 0);
	assert(destination == 1 && length == sizeof(first));
	assert(network_queue_demand_bytes(&queue, 1) == sizeof(second));
	assert(network_queue_pop(&queue, &destination, output, sizeof(output), &length) == 0);
	assert(destination == 1 && length == sizeof(second) && !memcmp(second, output, length));
	assert(network_queue_push(&queue, 3, first, sizeof(first)) == 0); /* wraps ring */
	assert(network_queue_peek(&queue, &destination, output, sizeof(output), &length) == 0);
	assert(destination == 3 && length == sizeof(first) && !memcmp(first, output, length));
	assert(network_queue_drop_front(&queue, &destination, &length) == 0);
	assert(destination == 3 && length == sizeof(first));
	assert(network_queue_pop(&queue, &destination, output, sizeof(output), &length) == -EAGAIN);
	assert(network_queue_drop_front(&queue, &destination, &length) == -EAGAIN);
	assert(network_queue_init(&queue, storage, NETWORK_QUEUE_MAX_BYTES + 1U) == -EINVAL);
}

static void test_blocks_and_reassembly(void)
{
	uint8_t raw[NETWORK_MAX_SERIAL_BLOCK], encoded[NETWORK_MAX_COMPRESSED_BLOCK];
	uint8_t output[NETWORK_MAX_SERIAL_BLOCK], wire_payload[NETWORK_FRAME_MAX_PAYLOAD];
	struct network_fragment fragments[NETWORK_MAX_FRAGMENTS], unpacked;
	struct network_reassembler reassembler;
	size_t encoded_length, fragment_count, packed_length, raw_length;
	uint32_t offset, received = 0, missing = 0;
	uint8_t codec;
	size_t i;
	const uint8_t sources[] = { 0, 1, 3, 8 };

	make_random_data(raw, sizeof(raw));
	assert(network_block_encode(raw, sizeof(raw), encoded, sizeof(encoded),
		&encoded_length, &codec) == 0);
	assert(codec == NETWORK_CODEC_RAW && encoded_length == sizeof(raw));
	assert(network_block_fragment(0x10203040U, 17, 65536, sizeof(raw), codec, encoded,
		encoded_length, fragments, NETWORK_MAX_FRAGMENTS, &fragment_count) == 0);
	assert(fragment_count == 26);
	assert(network_fragment_pack(&fragments[0], wire_payload, sizeof(wire_payload),
		&packed_length) == 0);
	assert(packed_length == 178 && packed_length <= NETWORK_FRAME_MAX_PAYLOAD);
	assert(network_fragment_unpack(wire_payload, packed_length, &unpacked) == 0);
	assert(unpacked.raw_offset == 65536 && unpacked.codec == NETWORK_CODEC_RAW);
	assert(network_fragment_unpack(wire_payload, packed_length - 1, &unpacked) == -EBADMSG);

	network_reassembler_init(&reassembler);
	for (i = 0; i < sizeof(sources); i++) {
		size_t j;
		uint8_t source = sources[i];
		for (j = fragment_count; j > 0; j--) {
			size_t index = j - 1U;
			int result;
			if (source == 3 && index == 2)
				continue;
			result = network_reassembler_add(&reassembler, source, &fragments[index],
				output, sizeof(output), &raw_length, &offset, &received, &missing);
			if (source == 3 && index == 0)
				assert(result == 0 && (missing & (1U << 2)));
			else if (source == 3)
				assert(result == 0);
			else if (j == 1)
				assert(result == 1);
			else
				assert(result == 0);
		}
		if (source == 3) {
			assert(network_reassembler_add(&reassembler, source, &fragments[2], output,
				sizeof(output), &raw_length, &offset, &received, &missing) == 1);
		}
		assert(raw_length == sizeof(raw) && offset == 65536 && missing == 0);
		assert(!memcmp(output, raw, sizeof(raw)));
	}

	/* Metadata changes cannot silently discard a partially received block. */
	assert(network_reassembler_add(&reassembler, 4, &fragments[0], output, sizeof(output),
		&raw_length, &offset, &received, &missing) == 0);
	fragments[1].block_id++;
	assert(network_reassembler_add(&reassembler, 4, &fragments[1], output, sizeof(output),
		&raw_length, &offset, &received, &missing) == -EBUSY);
	fragments[1].block_id--;
	assert(network_reassembler_add(&reassembler, NETWORK_MAX_ID + 1U, &fragments[0], output, sizeof(output),
		&raw_length, &offset, &received, &missing) == -EINVAL);

	memset(raw, 'A', sizeof(raw));
	assert(network_block_encode(raw, sizeof(raw), encoded, sizeof(encoded),
		&encoded_length, &codec) == 0);
	assert(codec == NETWORK_CODEC_DEFLATE && encoded_length < sizeof(raw));
	assert(network_block_decompress(encoded, encoded_length, sizeof(raw), output,
		sizeof(output), &raw_length) == 0);
	assert(raw_length == sizeof(raw) && !memcmp(raw, output, sizeof(raw)));
	assert(network_block_decompress(encoded, encoded_length - 1, sizeof(raw), output,
		sizeof(output), &raw_length) == -EBADMSG);
}

static void test_stream_flush(void)
{
	const uint8_t sample[] = { 'l', 'o', 'g', '\n' };
	struct network_stream_builder builder;
	struct network_fragment fragments[NETWORK_MAX_FRAGMENTS];
	size_t consumed, count;
	uint64_t flush_ms = 100U + NETWORK_BLOCK_FLUSH_MS;
	network_stream_builder_init(&builder, 99, 4, 1200);
	assert(network_stream_builder_append(&builder, sample, sizeof(sample), 100, &consumed) == 0);
	assert(consumed == sizeof(sample));
	assert(!network_stream_builder_flush_due(&builder, flush_ms - 1U));
	assert(network_stream_builder_flush_due(&builder, flush_ms));
	assert(network_stream_builder_take(&builder, flush_ms - 1U, false, fragments,
		NETWORK_MAX_FRAGMENTS, &count) == 0);
	assert(network_stream_builder_take(&builder, flush_ms, false, fragments,
		NETWORK_MAX_FRAGMENTS, &count) == 1);
	assert(count == 1 && fragments[0].block_id == 4 && fragments[0].raw_offset == 1200);
	assert(fragments[0].codec == NETWORK_CODEC_RAW && fragments[0].data_length == sizeof(sample));
	assert(network_stream_builder_take(&builder, flush_ms, true, fragments,
		NETWORK_MAX_FRAGMENTS, &count) == 0);
}

int main(void)
{
	test_join_auth_and_replay();
	test_scheduler_and_beacon();
	test_scheduler_one_and_three_nodes();
	test_packet_sized_scheduler();
	test_delayed_full_size_data_grant();
	test_timing_and_backoff();
	test_queue();
	test_blocks_and_reassembly();
	test_stream_flush();
	puts("network core tests: ok (1/3/8 nodes, replay, timing, queue, fragments)");
	return 0;
}
