/* SPDX-License-Identifier: GPL-2.0-only */
#include "network.h"

#include <errno.h>
#include <string.h>

#ifdef NETWORK_TEST_USE_OPENSSL
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#else
#include <mbedtls/md.h>
#endif

#define WIRE_MAGIC_0 0x52U
#define WIRE_MAGIC_1 0x4eU
#define WIRE_VERSION 1U

static void put_u16(uint8_t *out, uint16_t value)
{
	out[0] = (uint8_t)value;
	out[1] = (uint8_t)(value >> 8);
}

static uint16_t get_u16(const uint8_t *in)
{
	return (uint16_t)in[0] | ((uint16_t)in[1] << 8);
}

static void put_u32(uint8_t *out, uint32_t value)
{
	out[0] = (uint8_t)value;
	out[1] = (uint8_t)(value >> 8);
	out[2] = (uint8_t)(value >> 16);
	out[3] = (uint8_t)(value >> 24);
}

static uint32_t get_u32(const uint8_t *in)
{
	return (uint32_t)in[0] | ((uint32_t)in[1] << 8) |
		((uint32_t)in[2] << 16) | ((uint32_t)in[3] << 24);
}

static void put_u64(uint8_t *out, uint64_t value)
{
	put_u32(out, (uint32_t)value);
	put_u32(out + 4, (uint32_t)(value >> 32));
}

static uint64_t get_u64(const uint8_t *in)
{
	return (uint64_t)get_u32(in) | ((uint64_t)get_u32(in + 4) << 32);
}

static bool valid_id(uint8_t id)
{
	return id <= NETWORK_MAX_ID || id == NETWORK_BROADCAST_ID;
}

static bool valid_type(uint8_t type)
{
	return type >= NETWORK_FRAME_BEACON && type <= NETWORK_FRAME_COMMAND_RESPONSE;
}

static int make_tag(const uint8_t key[NETWORK_KEY_BYTES], const uint8_t *input,
	size_t input_length, uint8_t tag[32])
{
#ifdef NETWORK_TEST_USE_OPENSSL
	EVP_MAC *mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
	EVP_MAC_CTX *context;
	OSSL_PARAM parameters[2];
	size_t output_length = 0;
	int result = -EIO;
	if (!mac)
		return -EIO;
	context = EVP_MAC_CTX_new(mac);
	EVP_MAC_free(mac);
	if (!context)
		return -EIO;
	parameters[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, "SHA256", 0);
	parameters[1] = OSSL_PARAM_construct_end();
	if (EVP_MAC_init(context, key, NETWORK_KEY_BYTES, parameters) == 1 &&
	    EVP_MAC_update(context, input, input_length) == 1 &&
	    EVP_MAC_final(context, tag, &output_length, 32) == 1 && output_length == 32)
		result = 0;
	EVP_MAC_CTX_free(context);
	return result;
#else
	const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
	if (!md)
		return -EIO;
	return mbedtls_md_hmac(md, key, NETWORK_KEY_BYTES, input, input_length, tag) ?
		-EIO : 0;
#endif
}

static bool tag_equal(const uint8_t *a, const uint8_t *b, size_t length)
{
	uint8_t difference = 0;
	size_t i;
	for (i = 0; i < length; i++)
		difference |= a[i] ^ b[i];
	return difference == 0;
}

static bool sequence_is_newer(uint32_t candidate, uint32_t previous)
{
	uint32_t delta = candidate - previous;
	return delta != 0 && delta < 0x80000000U;
}

int network_frame_encode(const struct network_frame *frame,
	const uint8_t key[NETWORK_KEY_BYTES], uint8_t *output, size_t output_capacity,
	size_t *output_length)
{
	uint8_t full_tag[32];
	size_t frame_length;
	int result;

	if (!frame || !key || !output || !output_length || !frame->network_id ||
	    !valid_type(frame->type) || !valid_id(frame->source) ||
	    !valid_id(frame->destination) ||
	    frame->payload_length > NETWORK_FRAME_MAX_PAYLOAD)
		return -EINVAL;
	if (frame->source == NETWORK_UNASSIGNED_NODE_ID) {
		if (frame->type != NETWORK_FRAME_JOIN ||
		    frame->destination != NETWORK_CONTROLLER_ID || frame->payload_length != 8 ||
		    !frame->source_boot_nonce || frame->controller_boot_nonce)
			return -EINVAL;
	} else if (frame->source == NETWORK_CONTROLLER_ID) {
		if (!frame->controller_boot_nonce ||
		    frame->source_boot_nonce != frame->controller_boot_nonce)
			return -EINVAL;
	} else if (!frame->source_boot_nonce || frame->type == NETWORK_FRAME_JOIN ||
		   frame->controller_boot_nonce == 0) {
		return -EINVAL;
	}
	if (frame->type == NETWORK_FRAME_JOIN_RESPONSE &&
	    (frame->source != NETWORK_CONTROLLER_ID ||
	     frame->destination != NETWORK_UNASSIGNED_NODE_ID || frame->payload_length != 9))
		return -EINVAL;
	frame_length = NETWORK_FRAME_HEADER_BYTES + frame->payload_length + NETWORK_AUTH_TAG_BYTES;
	if (frame_length > output_capacity || frame_length > NETWORK_FRAME_MAX_BYTES)
		return -EMSGSIZE;

	output[0] = WIRE_MAGIC_0;
	output[1] = WIRE_MAGIC_1;
	output[2] = WIRE_VERSION;
	output[3] = frame->type;
	output[4] = frame->source;
	output[5] = frame->destination;
	put_u32(output + 6, frame->sequence);
	put_u32(output + 10, frame->network_id);
	put_u64(output + 14, frame->source_boot_nonce);
	put_u64(output + 22, frame->controller_boot_nonce);
	put_u16(output + 30, frame->payload_length);
	if (frame->payload_length)
		memcpy(output + NETWORK_FRAME_HEADER_BYTES, frame->payload, frame->payload_length);
	result = make_tag(key, output, NETWORK_FRAME_HEADER_BYTES + frame->payload_length, full_tag);
	if (result)
		return result;
	memcpy(output + NETWORK_FRAME_HEADER_BYTES + frame->payload_length,
		full_tag, NETWORK_AUTH_TAG_BYTES);
	memset(full_tag, 0, sizeof(full_tag));
	*output_length = frame_length;
	return 0;
}

void network_replay_init(struct network_replay_table *replay, uint8_t local_id,
	uint32_t network_id, uint64_t local_boot_nonce, uint64_t controller_boot_nonce)
{
	if (!replay)
		return;
	memset(replay, 0, sizeof(*replay));
	replay->local_id = local_id;
	replay->network_id = network_id;
	replay->local_boot_nonce = local_boot_nonce;
	replay->controller_boot_nonce = controller_boot_nonce;
	replay->initialized = network_id != 0 &&
		(local_id <= NETWORK_MAX_ID || local_id == NETWORK_UNASSIGNED_NODE_ID) &&
		local_boot_nonce != 0 && (local_id != NETWORK_CONTROLLER_ID ||
		controller_boot_nonce == local_boot_nonce);
}

int network_replay_set_controller_nonce(struct network_replay_table *replay,
	uint64_t controller_boot_nonce)
{
	if (!replay || !replay->initialized || !controller_boot_nonce)
		return -EINVAL;
	if (replay->controller_boot_nonce && replay->controller_boot_nonce != controller_boot_nonce)
		return -ESTALE;
	replay->controller_boot_nonce = controller_boot_nonce;
	return 0;
}

int network_replay_bind_node(struct network_replay_table *replay, uint8_t assigned_id,
	uint64_t node_boot_nonce, uint32_t join_sequence)
{
	struct network_replay_entry *entry;
	if (!replay || !replay->initialized || replay->local_id != NETWORK_CONTROLLER_ID ||
	    assigned_id < NETWORK_FIRST_NODE_ID || assigned_id > NETWORK_MAX_ID ||
	    !node_boot_nonce)
		return -EINVAL;
	entry = &replay->by_source[assigned_id];
	entry->source_boot_nonce = node_boot_nonce;
	entry->sequence = join_sequence;
	entry->initialized = true;
	return 0;
}

int network_join_payload_encode(const uint8_t eui[8], uint8_t output[8])
{
	uint8_t any = 0, all_ff = 0xff;
	size_t i;
	if (!eui || !output)
		return -EINVAL;
	for (i = 0; i < 8; i++) {
		any |= eui[i];
		all_ff &= eui[i];
	}
	if (!any || all_ff == 0xff)
		return -EINVAL;
	memcpy(output, eui, 8);
	return 0;
}

int network_join_response_payload_encode(uint8_t assigned_id, uint64_t node_boot_nonce,
	uint8_t output[9])
{
	if (assigned_id < NETWORK_FIRST_NODE_ID || assigned_id > NETWORK_MAX_ID ||
	    !node_boot_nonce || !output)
		return -EINVAL;
	output[0] = assigned_id;
	put_u64(output + 1, node_boot_nonce);
	return 0;
}

int network_frame_peek(const uint8_t *input, size_t input_length, struct network_frame *frame)
{
	uint16_t payload_length;
	if (!input || !frame || input_length < NETWORK_FRAME_OVERHEAD ||
	    input_length > NETWORK_FRAME_MAX_BYTES)
		return -EINVAL;
	if (input[0] != WIRE_MAGIC_0 || input[1] != WIRE_MAGIC_1 || input[2] != WIRE_VERSION ||
	    !valid_type(input[3]) || !valid_id(input[4]) || !valid_id(input[5]))
		return -EBADMSG;
	if (input[4] == NETWORK_UNASSIGNED_NODE_ID && input[3] != NETWORK_FRAME_JOIN)
		return -EBADMSG;
	payload_length = get_u16(input + 30);
	if (payload_length > NETWORK_FRAME_MAX_PAYLOAD ||
	    input_length != NETWORK_FRAME_HEADER_BYTES + payload_length + NETWORK_AUTH_TAG_BYTES)
		return -EMSGSIZE;
	if ((input[3] == NETWORK_FRAME_JOIN &&
	     (input[4] != NETWORK_UNASSIGNED_NODE_ID || input[5] != NETWORK_CONTROLLER_ID ||
	      payload_length != 8)) ||
	    (input[3] == NETWORK_FRAME_JOIN_RESPONSE &&
	     (input[4] != NETWORK_CONTROLLER_ID || input[5] != NETWORK_UNASSIGNED_NODE_ID ||
	      payload_length != 9)))
		return -EBADMSG;
	memset(frame, 0, sizeof(*frame));
	frame->type = input[3];
	frame->source = input[4];
	frame->destination = input[5];
	frame->sequence = get_u32(input + 6);
	frame->network_id = get_u32(input + 10);
	frame->source_boot_nonce = get_u64(input + 14);
	frame->controller_boot_nonce = get_u64(input + 22);
	frame->payload_length = payload_length;
	memcpy(frame->payload, input + NETWORK_FRAME_HEADER_BYTES, payload_length);
	return 0;
}

int network_frame_decode(const uint8_t *input, size_t input_length,
	const uint8_t key[NETWORK_KEY_BYTES], struct network_replay_table *replay,
	struct network_frame *frame)
{
	uint8_t full_tag[32];
	uint16_t payload_length;
	uint64_t controller_nonce, source_nonce;
	uint32_t sequence;
	uint8_t source, type;
	struct network_replay_entry *entry;
	struct network_join_replay_entry *join_entry = NULL;
	int result;

	if (!input || !key || !replay || !frame || !replay->initialized ||
	    input_length < NETWORK_FRAME_OVERHEAD || input_length > NETWORK_FRAME_MAX_BYTES)
		return -EINVAL;
	if (input[0] != WIRE_MAGIC_0 || input[1] != WIRE_MAGIC_1 || input[2] != WIRE_VERSION)
		return -EBADMSG;
	type = input[3];
	source = input[4];
	if (!valid_type(type) || !valid_id(source) ||
	    !valid_id(input[5]))
		return -EBADMSG;
	payload_length = get_u16(input + 30);
	if (payload_length > NETWORK_FRAME_MAX_PAYLOAD ||
	    input_length != NETWORK_FRAME_HEADER_BYTES + payload_length + NETWORK_AUTH_TAG_BYTES)
		return -EMSGSIZE;
	result = make_tag(key, input, NETWORK_FRAME_HEADER_BYTES + payload_length, full_tag);
	if (result)
		return result;
	if (!tag_equal(full_tag, input + NETWORK_FRAME_HEADER_BYTES + payload_length,
		NETWORK_AUTH_TAG_BYTES)) {
		memset(full_tag, 0, sizeof(full_tag));
		return -EACCES;
	}
	memset(full_tag, 0, sizeof(full_tag));

	if (get_u32(input + 10) != replay->network_id)
		return -EACCES;
	sequence = get_u32(input + 6);
	source_nonce = get_u64(input + 14);
	controller_nonce = get_u64(input + 22);
	if (!source_nonce)
		return -EBADMSG;
	if (source == NETWORK_UNASSIGNED_NODE_ID) {
		if (type != NETWORK_FRAME_JOIN || replay->local_id != NETWORK_CONTROLLER_ID ||
		    input[5] != NETWORK_CONTROLLER_ID || payload_length != 8 || controller_nonce != 0)
			return -EACCES;
	} else if (source == NETWORK_CONTROLLER_ID) {
		if (source_nonce != controller_nonce)
			return -EBADMSG;
		if (type == NETWORK_FRAME_JOIN_RESPONSE) {
			if (replay->local_id == NETWORK_CONTROLLER_ID ||
			    input[5] != NETWORK_UNASSIGNED_NODE_ID || payload_length != 9 ||
			    get_u64(input + NETWORK_FRAME_HEADER_BYTES + 1) != replay->local_boot_nonce ||
			    input[NETWORK_FRAME_HEADER_BYTES] < NETWORK_FIRST_NODE_ID ||
			    input[NETWORK_FRAME_HEADER_BYTES] > NETWORK_MAX_ID)
				return -EACCES;
			if (controller_nonce != replay->controller_boot_nonce &&
			    (controller_nonce == replay->previous_controller_boot_nonces[0] ||
			     controller_nonce == replay->previous_controller_boot_nonces[1]))
				return -ESTALE;
		} else if (!replay->controller_boot_nonce ||
			   controller_nonce != replay->controller_boot_nonce ||
			   (input[5] != NETWORK_BROADCAST_ID && input[5] != replay->local_id)) {
			return -ESTALE;
		}
	} else {
		if (replay->local_id != NETWORK_CONTROLLER_ID || type == NETWORK_FRAME_JOIN)
			return -EACCES;
		if (!controller_nonce || controller_nonce != replay->controller_boot_nonce) {
			return -ESTALE;
		}
	}

	if (source == NETWORK_UNASSIGNED_NODE_ID) {
		size_t i, free_slot = NETWORK_MAX_NODES;
		uint8_t checked_eui[8];
		if (network_join_payload_encode(input + NETWORK_FRAME_HEADER_BYTES, checked_eui))
			return -EBADMSG;
		for (i = 0; i < NETWORK_MAX_NODES; i++) {
			if (replay->join_by_eui[i].initialized &&
			    !memcmp(replay->join_by_eui[i].eui,
				input + NETWORK_FRAME_HEADER_BYTES, 8)) {
				join_entry = &replay->join_by_eui[i];
				break;
			}
			if (!replay->join_by_eui[i].initialized && free_slot == NETWORK_MAX_NODES)
				free_slot = i;
		}
		if (!join_entry) {
			if (free_slot == NETWORK_MAX_NODES)
				return -ENOSPC;
			join_entry = &replay->join_by_eui[free_slot];
			memset(join_entry, 0, sizeof(*join_entry));
			memcpy(join_entry->eui, input + NETWORK_FRAME_HEADER_BYTES, 8);
		}
		if (join_entry->initialized) {
			if (source_nonce != join_entry->source_boot_nonce) {
				if (source_nonce == join_entry->previous_boot_nonces[0] ||
				    source_nonce == join_entry->previous_boot_nonces[1])
					return -ESTALE;
			join_entry->previous_boot_nonces[1] = join_entry->previous_boot_nonces[0];
			join_entry->previous_boot_nonces[0] = join_entry->source_boot_nonce;
			} else if (!sequence_is_newer(sequence, join_entry->sequence)) {
				return -EALREADY;
			}
		}
		join_entry->source_boot_nonce = source_nonce;
		join_entry->sequence = sequence;
		join_entry->initialized = true;
	} else {
		entry = &replay->by_source[source];
		if (entry->initialized && source_nonce != entry->source_boot_nonce) {
			if (source != NETWORK_CONTROLLER_ID || type != NETWORK_FRAME_JOIN_RESPONSE)
				return -ESTALE;
			entry->initialized = false;
		}
		if (entry->initialized && !sequence_is_newer(sequence, entry->sequence))
			return -EALREADY;
		entry->source_boot_nonce = source_nonce;
		entry->sequence = sequence;
		entry->initialized = true;
		if (source == NETWORK_CONTROLLER_ID && type == NETWORK_FRAME_JOIN_RESPONSE) {
			if (replay->controller_boot_nonce &&
			    replay->controller_boot_nonce != controller_nonce) {
				replay->previous_controller_boot_nonces[1] =
					replay->previous_controller_boot_nonces[0];
				replay->previous_controller_boot_nonces[0] =
					replay->controller_boot_nonce;
			}
			replay->controller_boot_nonce = controller_nonce;
			replay->local_id = input[NETWORK_FRAME_HEADER_BYTES];
		}
	}

	memset(frame, 0, sizeof(*frame));
	frame->type = type;
	frame->source = source;
	frame->destination = input[5];
	frame->sequence = sequence;
	frame->network_id = get_u32(input + 10);
	frame->source_boot_nonce = source_nonce;
	frame->controller_boot_nonce = controller_nonce;
	frame->payload_length = payload_length;
	if (payload_length)
		memcpy(frame->payload, input + NETWORK_FRAME_HEADER_BYTES, payload_length);
	return 0;
}

static void put_u16_local(uint8_t *out, uint16_t value)
{
	put_u16(out, value);
}

int network_beacon_encode(const struct network_beacon *beacon, uint8_t *output,
	size_t output_capacity, size_t *output_length)
{
	size_t position = 0, i;
	uint64_t previous_end = 0;
	size_t required;
	if (!beacon || !output || !output_length ||
	    beacon->contention_ms != NETWORK_CONTENTION_MS ||
	    !beacon->downlink_ms ||
	    beacon->grant_count > NETWORK_MAX_GRANTS ||
	    beacon->acknowledgement_count > NETWORK_MAX_ACK_ENTRIES)
		return -EINVAL;
	if ((uint32_t)beacon->contention_ms + beacon->downlink_ms +
	    2U * NETWORK_GUARD_MS >= NETWORK_FRAME_MS)
		return -EINVAL;
	if (beacon->has_command && (beacon->command.target_node_id < NETWORK_FIRST_NODE_ID ||
	    beacon->command.target_node_id > NETWORK_MAX_ID || !beacon->command.length))
		return -EINVAL;
	if (beacon->has_command &&
	    beacon->command.length > NETWORK_BEACON_COMMAND_MAX_BYTES)
		return -EMSGSIZE;
	required = 10U + 5U * beacon->grant_count +
		11U * beacon->acknowledgement_count +
		(beacon->has_command ? 16U + beacon->command.length : 0U);
	if (required > output_capacity || required > NETWORK_FRAME_MAX_PAYLOAD)
		return -EMSGSIZE;
	put_u32(output + position, beacon->frame_number); position += 4;
	put_u16_local(output + position, beacon->contention_ms); position += 2;
	put_u16_local(output + position, beacon->downlink_ms); position += 2;
	output[position++] = beacon->grant_count;
	for (i = 0; i < beacon->grant_count; i++) {
		const struct network_grant *grant = &beacon->grants[i];
		if (grant->node_id < NETWORK_FIRST_NODE_ID || grant->node_id > NETWORK_MAX_ID ||
		    !grant->airtime_budget_us || grant->start_offset_us % 1000U ||
		    grant->airtime_budget_us % 1000U || grant->start_offset_us / 1000U > UINT16_MAX ||
		    grant->airtime_budget_us / 1000U > UINT16_MAX ||
		    grant->start_offset_us < ((uint32_t)beacon->downlink_ms + NETWORK_GUARD_MS) * 1000U ||
		    grant->start_offset_us + (uint64_t)grant->airtime_budget_us >
		    (NETWORK_FRAME_MS - beacon->contention_ms - NETWORK_GUARD_MS) * 1000ULL ||
		    (i && grant->start_offset_us < previous_end + NETWORK_GUARD_MS * 1000ULL))
			return -EINVAL;
		output[position++] = grant->node_id;
		put_u16(output + position, (uint16_t)(grant->start_offset_us / 1000U)); position += 2;
		put_u16(output + position, (uint16_t)(grant->airtime_budget_us / 1000U)); position += 2;
		previous_end = (uint64_t)grant->start_offset_us + grant->airtime_budget_us;
	}
	output[position++] = beacon->acknowledgement_count;
	for (i = 0; i < beacon->acknowledgement_count; i++) {
		const struct network_ack_entry *ack = &beacon->acknowledgements[i];
		if (ack->node_id < NETWORK_FIRST_NODE_ID || ack->node_id > NETWORK_MAX_ID)
			return -EINVAL;
		output[position++] = ack->node_id;
		put_u32(output + position, ack->stream_id); position += 4;
		put_u16(output + position, ack->block_id); position += 2;
		put_u32(output + position, ack->received_bitmap); position += 4;
	}
	if (beacon->has_command) {
		output[position++] = beacon->command.target_node_id;
		put_u16(output + position, beacon->command.sequence); position += 2;
		output[position++] = beacon->command.length;
		memcpy(output + position, beacon->command.bytes, beacon->command.length);
		position += beacon->command.length;
		memcpy(output + position, beacon->command.tag, NETWORK_AUTH_TAG_BYTES);
		position += NETWORK_AUTH_TAG_BYTES;
	}
	*output_length = position;
	return 0;
}

int network_beacon_decode(const uint8_t *input, size_t input_length,
	struct network_beacon *beacon)
{
	size_t position = 0, i;
	uint8_t grant_count, ack_count;
	uint64_t previous_end = 0;
	if (!input || !beacon || input_length < 10)
		return -EINVAL;
	memset(beacon, 0, sizeof(*beacon));
	beacon->frame_number = get_u32(input); position = 4;
	beacon->contention_ms = get_u16(input + position); position += 2;
	beacon->downlink_ms = get_u16(input + position); position += 2;
	grant_count = input[position++];
	if (beacon->contention_ms != NETWORK_CONTENTION_MS ||
	    !beacon->downlink_ms ||
	    (uint32_t)beacon->contention_ms + beacon->downlink_ms +
	    2U * NETWORK_GUARD_MS >= NETWORK_FRAME_MS ||
	    grant_count > NETWORK_MAX_GRANTS ||
	    input_length < position + (size_t)grant_count * 5U + 1U)
		return -EBADMSG;
	beacon->grant_count = grant_count;
	for (i = 0; i < grant_count; i++) {
		struct network_grant *grant = &beacon->grants[i];
		grant->node_id = input[position++];
		grant->start_offset_us = (uint32_t)get_u16(input + position) * 1000U; position += 2;
		grant->airtime_budget_us = (uint32_t)get_u16(input + position) * 1000U; position += 2;
		if (grant->node_id < NETWORK_FIRST_NODE_ID || grant->node_id > NETWORK_MAX_ID ||
		    !grant->airtime_budget_us || grant->start_offset_us <
		    ((uint32_t)beacon->downlink_ms + NETWORK_GUARD_MS) * 1000U ||
		    grant->start_offset_us + grant->airtime_budget_us >
		    (NETWORK_FRAME_MS - beacon->contention_ms - NETWORK_GUARD_MS) * 1000U ||
		    (i && grant->start_offset_us < previous_end + NETWORK_GUARD_MS * 1000U))
			return -EBADMSG;
		previous_end = (uint64_t)grant->start_offset_us + grant->airtime_budget_us;
	}
	ack_count = input[position++];
	if (ack_count > NETWORK_MAX_ACK_ENTRIES ||
	    input_length < position + (size_t)ack_count * 11U)
		return -EBADMSG;
	beacon->acknowledgement_count = ack_count;
	for (i = 0; i < ack_count; i++) {
		struct network_ack_entry *ack = &beacon->acknowledgements[i];
		ack->node_id = input[position++];
		ack->stream_id = get_u32(input + position); position += 4;
		ack->block_id = get_u16(input + position); position += 2;
		ack->received_bitmap = get_u32(input + position); position += 4;
		if (ack->node_id < NETWORK_FIRST_NODE_ID || ack->node_id > NETWORK_MAX_ID)
			return -EBADMSG;
	}
	if (position != input_length) {
		size_t command_length;
		if (input_length - position < 16U)
			return -EBADMSG;
		beacon->command.target_node_id = input[position++];
		beacon->command.sequence = get_u16(input + position); position += 2;
		command_length = input[position++];
		if (beacon->command.target_node_id < NETWORK_FIRST_NODE_ID ||
		    beacon->command.target_node_id > NETWORK_MAX_ID || !command_length ||
		    command_length > NETWORK_BEACON_COMMAND_MAX_BYTES ||
		    input_length != position + command_length + NETWORK_AUTH_TAG_BYTES)
			return -EBADMSG;
		beacon->command.length = (uint8_t)command_length;
		memcpy(beacon->command.bytes, input + position, command_length);
		position += command_length;
		memcpy(beacon->command.tag, input + position, NETWORK_AUTH_TAG_BYTES);
		beacon->has_command = true;
	}
	return 0;
}

int network_beacon_command_sign(const struct network_beacon_command *command,
	uint32_t network_id, uint64_t controller_boot_nonce, uint32_t frame_number,
	const uint8_t key[NETWORK_KEY_BYTES], uint8_t tag[NETWORK_AUTH_TAG_BYTES])
{
	uint8_t authenticated[24U + NETWORK_BEACON_COMMAND_MAX_BYTES];
	uint8_t full_tag[32];
	size_t length;
	int result;
	if (!command || !network_id || !controller_boot_nonce || !key || !tag ||
	    command->target_node_id < NETWORK_FIRST_NODE_ID ||
	    command->target_node_id > NETWORK_MAX_ID || !command->length)
		return -EINVAL;
	if (command->length > NETWORK_BEACON_COMMAND_MAX_BYTES)
		return -EMSGSIZE;
	length = 24U + command->length;
	authenticated[0] = 'R';
	authenticated[1] = 'T';
	authenticated[2] = 'C';
	authenticated[3] = WIRE_VERSION;
	put_u32(authenticated + 4, network_id);
	put_u64(authenticated + 8, controller_boot_nonce);
	put_u32(authenticated + 16, frame_number);
	authenticated[20] = command->target_node_id;
	put_u16(authenticated + 21, command->sequence);
	authenticated[23] = command->length;
	memcpy(authenticated + 24, command->bytes, command->length);
	result = make_tag(key, authenticated, length, full_tag);
	if (result)
		return result;
	memcpy(tag, full_tag, NETWORK_AUTH_TAG_BYTES);
	memset(full_tag, 0, sizeof(full_tag));
	return 0;
}

int network_beacon_command_verify(const struct network_beacon *beacon, uint32_t network_id,
	uint64_t controller_boot_nonce, const uint8_t key[NETWORK_KEY_BYTES])
{
	uint8_t expected[NETWORK_AUTH_TAG_BYTES];
	int result;
	if (!beacon || !beacon->has_command || !key)
		return -EINVAL;
	result = network_beacon_command_sign(&beacon->command, network_id,
		controller_boot_nonce, beacon->frame_number, key, expected);
	if (result)
		return result;
	return tag_equal(expected, beacon->command.tag, sizeof(expected)) ? 0 : -EACCES;
}
