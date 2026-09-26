/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef REMOTE_TESTER_NETWORK_H
#define REMOTE_TESTER_NETWORK_H

/*
 * Small, allocation-free MT7628 star-network protocol core.
 *
 * Time values are microseconds unless a name ends in _ms. Wire integers are
 * little-endian. The daemon owns the radio, clock, random source, key storage,
 * and queue backing memory; this module has no thread or hardware callbacks.
 */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>

#define NETWORK_CONTROLLER_ID       0U
#define NETWORK_FIRST_NODE_ID       1U
#define NETWORK_MAX_NODES           8U
#define NETWORK_MAX_ID              NETWORK_MAX_NODES
#define NETWORK_BROADCAST_ID        0xffU
#define NETWORK_UNASSIGNED_NODE_ID  NETWORK_BROADCAST_ID
#define NETWORK_KEY_BYTES           32U
#define NETWORK_AUTH_TAG_BYTES      12U
#define NETWORK_FRAME_MAX_BYTES     240U
#define NETWORK_FRAME_HEADER_BYTES  32U
#define NETWORK_FRAME_OVERHEAD      (NETWORK_FRAME_HEADER_BYTES + NETWORK_AUTH_TAG_BYTES)
#define NETWORK_FRAME_MAX_PAYLOAD   (NETWORK_FRAME_MAX_BYTES - NETWORK_FRAME_OVERHEAD)
#define NETWORK_FRAME_MS            2000U
#define NETWORK_CONTENTION_MS       250U
#define NETWORK_GUARD_MS             20U
#define NETWORK_TX_START_MARGIN_MS    2U
#define NETWORK_DEFAULT_DOWNLINK_MS  200U
#define NETWORK_MAX_SERIAL_BLOCK     4096U
#define NETWORK_FRAGMENT_HEADER_BYTES 18U
#define NETWORK_FRAGMENT_DATA_BYTES  160U
#define NETWORK_DATA_FRAME_MAX_BYTES \
	(NETWORK_FRAME_OVERHEAD + NETWORK_FRAGMENT_HEADER_BYTES + NETWORK_FRAGMENT_DATA_BYTES)
#define NETWORK_MAX_FRAGMENTS        32U
#define NETWORK_MAX_COMPRESSED_BLOCK (NETWORK_FRAGMENT_DATA_BYTES * NETWORK_MAX_FRAGMENTS)
#define NETWORK_MAX_RETRIES           5U
#define NETWORK_BLOCK_FLUSH_MS        3000U
#define NETWORK_QUEUE_MAX_BYTES       (2U * 1024U * 1024U)
#define NETWORK_MAX_GRANTS            16U
#define NETWORK_MAX_ACK_ENTRIES       NETWORK_MAX_NODES
#define NETWORK_SYNC_LOSS_FRAMES      1U
#define NETWORK_BEACON_COMMAND_MAX_BYTES 64U

enum network_frame_type {
	NETWORK_FRAME_BEACON = 1,
	NETWORK_FRAME_JOIN = 2,
	NETWORK_FRAME_SLOT_REQUEST = 3,
	NETWORK_FRAME_GRANT = 4,
	NETWORK_FRAME_ACK = 5,
	NETWORK_FRAME_DATA = 6,
	NETWORK_FRAME_SYNC = 7,
	NETWORK_FRAME_JOIN_RESPONSE = 8,
	NETWORK_FRAME_STATUS = 9,
	NETWORK_FRAME_COMMAND = 10,
	NETWORK_FRAME_COMMAND_RESPONSE = 11,
};

struct network_frame {
	uint8_t type;
	uint8_t source;
	uint8_t destination;
	uint32_t sequence;
	uint32_t network_id;
	uint64_t source_boot_nonce;
	uint64_t controller_boot_nonce;
	uint16_t payload_length;
	uint8_t payload[NETWORK_FRAME_MAX_PAYLOAD];
};

struct network_replay_entry {
	uint32_t sequence;
	uint64_t source_boot_nonce;
	bool initialized;
};

struct network_join_replay_entry {
	uint8_t eui[8];
	uint64_t source_boot_nonce;
	uint64_t previous_boot_nonces[2];
	uint32_t sequence;
	bool initialized;
};

struct network_replay_table {
	uint32_t network_id;
	uint64_t controller_boot_nonce;
	uint64_t previous_controller_boot_nonces[2];
	uint64_t local_boot_nonce;
	uint8_t local_id;
	bool initialized;
	struct network_replay_entry by_source[NETWORK_MAX_ID + 1U];
	struct network_join_replay_entry join_by_eui[NETWORK_MAX_NODES];
};

/* Wire framing authenticates header and payload with HMAC-SHA256/96. */
int network_frame_encode(const struct network_frame *frame,
	const uint8_t key[NETWORK_KEY_BYTES], uint8_t *output, size_t output_capacity,
	size_t *output_length);
int network_frame_decode(const uint8_t *input, size_t input_length,
	const uint8_t key[NETWORK_KEY_BYTES], struct network_replay_table *replay,
	struct network_frame *frame);
/* Structural peek only; all returned fields are untrusted until decode succeeds. */
int network_frame_peek(const uint8_t *input, size_t input_length, struct network_frame *frame);
void network_replay_init(struct network_replay_table *replay, uint8_t local_id,
	uint32_t network_id, uint64_t local_boot_nonce, uint64_t controller_boot_nonce);
/* Initialize a candidate beacon session while preserving/rejecting retired epochs. */
static inline int network_replay_init_successor(struct network_replay_table *next,
	const struct network_replay_table *current, uint8_t local_id, uint32_t network_id,
	uint64_t local_boot_nonce, uint64_t candidate_controller_nonce)
{
	uint64_t retired[2] = { 0, 0 };
	unsigned i;
	if (!next || next == current || !network_id || !local_boot_nonce ||
	    !candidate_controller_nonce || local_id == NETWORK_CONTROLLER_ID ||
	    (local_id > NETWORK_MAX_ID && local_id != NETWORK_UNASSIGNED_NODE_ID))
		return -EINVAL;
	if (current && current->initialized) {
		if (current->network_id != network_id ||
		    current->local_boot_nonce != local_boot_nonce ||
		    current->local_id == NETWORK_CONTROLLER_ID)
			return -EINVAL;
		if (candidate_controller_nonce == current->controller_boot_nonce)
			return -ESTALE;
		for (i = 0; i < 2; i++) {
			if (candidate_controller_nonce == current->previous_controller_boot_nonces[i])
				return -ESTALE;
			retired[i] = current->previous_controller_boot_nonces[i];
		}
		if (current->controller_boot_nonce) {
			retired[1] = retired[0];
			retired[0] = current->controller_boot_nonce;
		}
	}
	network_replay_init(next, local_id, network_id, local_boot_nonce,
		candidate_controller_nonce);
	if (!next->initialized)
		return -EINVAL;
	memcpy(next->previous_controller_boot_nonces, retired, sizeof(retired));
	return 0;
}
/* Rejoin without erasing current/retired controller nonces or replay sequence. */
static inline int network_replay_begin_join(struct network_replay_table *replay)
{
	if (!replay || !replay->initialized || replay->local_id == NETWORK_CONTROLLER_ID)
		return -EINVAL;
	replay->local_id = NETWORK_UNASSIGNED_NODE_ID;
	return 0;
}
int network_replay_set_controller_nonce(struct network_replay_table *replay,
	uint64_t controller_boot_nonce);
/* Controller calls after assigning an authenticated EUI JOIN to radio ID. */
int network_replay_bind_node(struct network_replay_table *replay, uint8_t assigned_id,
	uint64_t node_boot_nonce, uint32_t join_sequence);

/* JOIN carries an 8-byte stable EUI; JOIN_RESPONSE is ID + 8-byte nonce echo. */
int network_join_payload_encode(const uint8_t eui[8], uint8_t output[8]);
int network_join_response_payload_encode(uint8_t assigned_id, uint64_t node_boot_nonce,
	uint8_t output[9]);

struct network_ack_entry {
	uint8_t node_id;
	uint32_t stream_id;
	uint16_t block_id;
	uint32_t received_bitmap;
};

struct network_beacon_command {
	uint8_t target_node_id;
	uint16_t sequence;
	uint8_t length;
	uint8_t bytes[NETWORK_BEACON_COMMAND_MAX_BYTES];
	uint8_t tag[NETWORK_AUTH_TAG_BYTES];
};

struct network_grant {
	uint8_t node_id;
	uint32_t start_offset_us;
	uint32_t airtime_budget_us;
};

/* Beacon uses ms-granular grant boundaries; repeated node IDs are allowed. */
struct network_beacon {
	uint32_t frame_number;
	uint16_t contention_ms;
	uint16_t downlink_ms;
	struct network_grant grants[NETWORK_MAX_GRANTS];
	uint8_t grant_count;
	struct network_ack_entry acknowledgements[NETWORK_MAX_ACK_ENTRIES];
	uint8_t acknowledgement_count;
	bool has_command;
	struct network_beacon_command command;
};
int network_beacon_encode(const struct network_beacon *beacon, uint8_t *output,
	size_t output_capacity, size_t *output_length);
int network_beacon_decode(const uint8_t *input, size_t input_length,
	struct network_beacon *beacon);
int network_beacon_command_sign(const struct network_beacon_command *command,
	uint32_t network_id, uint64_t controller_boot_nonce, uint32_t frame_number,
	const uint8_t key[NETWORK_KEY_BYTES], uint8_t tag[NETWORK_AUTH_TAG_BYTES]);
int network_beacon_command_verify(const struct network_beacon *beacon, uint32_t network_id,
	uint64_t controller_boot_nonce, const uint8_t key[NETWORK_KEY_BYTES]);

/* demands[node_id - 1] is the requested airtime from node IDs 1 through 8. */
struct network_demand {
	bool joined;
	uint32_t requested_airtime_us;
};

struct network_scheduler {
	uint32_t max_airtime_per_frame_us;
	uint16_t downlink_ms;
};

/* Clips requested airtime to the frame capacity after downlink/contention/guards. */
int network_scheduler_init(struct network_scheduler *scheduler, uint32_t airtime_budget_us,
	uint16_t downlink_ms);
/* Demand is in airtime; every output is one complete packet window >= minimum. */
int network_scheduler_build_grants(struct network_scheduler *scheduler, uint32_t frame_number,
	const struct network_demand demands[NETWORK_MAX_NODES],
	uint32_t minimum_packet_airtime_us, struct network_grant *grants,
	size_t grant_capacity, size_t *grant_count);

enum network_node_state {
	NETWORK_NODE_UNJOINED = 0,
	NETWORK_NODE_JOINING,
	NETWORK_NODE_SYNCED,
	NETWORK_NODE_SYNC_LOST,
};

struct network_node_link {
	uint8_t node_id;
	uint8_t eui[8];
	enum network_node_state state;
	uint32_t last_beacon_frame;
	uint64_t frame_start_us;
	uint32_t synced_frame;
	uint32_t network_id;
	uint64_t node_boot_nonce;
	uint64_t controller_boot_nonce;
	struct network_grant grants[NETWORK_MAX_GRANTS];
	uint8_t grant_count;
	bool joined;
};

void network_node_init(struct network_node_link *node, uint32_t network_id,
	uint64_t node_boot_nonce, const uint8_t eui[8]);
int network_node_begin_join(struct network_node_link *node);
int network_node_build_join(const struct network_node_link *node, uint32_t sequence,
	struct network_frame *frame);
int network_node_observe_join_response(struct network_node_link *node,
	const struct network_frame *response);
int network_node_observe_beacon(struct network_node_link *node,
	const struct network_frame *frame, uint64_t frame_start_us);
bool network_node_check_sync(struct network_node_link *node, uint32_t current_frame_number);
/* True only inside this node's granted interval; direct grants do not use CAD. */
bool network_node_tx_window(const struct network_node_link *node, uint32_t frame_number,
	uint64_t now_us, uint32_t packet_airtime_us);

/* Caller runs CAD. Backoff is used only in the 500 ms contention interval. */
uint32_t network_contention_slot_time_ms(uint8_t spreading_factor,
	uint32_t bandwidth_khz, uint8_t cad_symbols);
uint32_t network_contention_backoff_ms(uint8_t attempt, uint32_t random_value,
	uint32_t base_slot_ms, uint32_t cap_ms);
bool network_contention_tx_allowed(bool in_contention_window, bool cad_clear,
	bool backoff_expired);
bool network_retry_allowed(uint8_t retries_already_used);

struct network_subslot_timing {
	uint8_t assigned_subslot;
	uint32_t tx_start_offset_us;
	uint32_t tx_window_us;
	uint32_t subslot_duration_us;
};
/* Guard/trailing-guard subslot arithmetic adapted from LoRaMesher v1.0.0. */
int network_subslot_compute(uint32_t slot_duration_us, uint8_t subslot_count,
	uint32_t guard_us, uint16_t identifier, struct network_subslot_timing *timing);

/* Single caller-owned FIFO; backing storage includes record headers.
 * Capacity includes 3 bytes of per-record header and is limited to 2 MiB. */
struct network_queue {
	uint8_t *storage;
	size_t capacity;
	size_t head;
	size_t tail;
	size_t used;
	size_t bytes_by_node[NETWORK_MAX_ID + 1U];
};

int network_queue_init(struct network_queue *queue, uint8_t *storage, size_t capacity);
int network_queue_push(struct network_queue *queue, uint8_t destination,
	const uint8_t *bytes, size_t length);
/* Peek copies the head record without consuming it; ENOSPC reports required length. */
int network_queue_peek(const struct network_queue *queue, uint8_t *destination,
	uint8_t *bytes, size_t output_capacity, size_t *length);
/* Drop only the current head record, typically after its destination accepts it. */
int network_queue_drop_front(struct network_queue *queue, uint8_t *destination,
	size_t *length);
int network_queue_pop(struct network_queue *queue, uint8_t *destination,
	uint8_t *bytes, size_t output_capacity, size_t *length);
size_t network_queue_demand_bytes(const struct network_queue *queue, uint8_t destination);

struct network_fragment {
	uint32_t stream_id;
	uint16_t block_id;
	uint32_t raw_offset;
	uint8_t index;
	uint8_t count;
	uint8_t codec;
	uint16_t raw_length;
	uint16_t compressed_length;
	uint16_t data_length;
	uint8_t data[NETWORK_FRAGMENT_DATA_BYTES];
};

struct network_reassembly_slot {
	uint32_t stream_id;
	uint16_t block_id;
	uint32_t raw_offset;
	uint16_t raw_length;
	uint16_t compressed_length;
	uint8_t count;
	uint8_t codec;
	uint32_t received_bitmap;
	bool active;
	uint8_t compressed[NETWORK_MAX_COMPRESSED_BLOCK];
};

struct network_reassembler {
	struct network_reassembly_slot by_source[NETWORK_MAX_ID + 1U];
};

struct network_stream_builder {
	uint32_t stream_id;
	uint32_t next_raw_offset;
	uint64_t last_append_ms;
	uint16_t next_block_id;
	size_t pending_length;
	uint8_t pending[NETWORK_MAX_SERIAL_BLOCK];
};

/* Each input block is compressed independently using raw DEFLATE. */
int network_block_compress(const uint8_t *input, size_t input_length,
	uint8_t *output, size_t output_capacity, size_t *output_length);
int network_block_decompress(const uint8_t *input, size_t input_length,
	size_t expected_output_length, uint8_t *output, size_t output_capacity,
	size_t *output_length);
enum network_block_codec {
	NETWORK_CODEC_RAW = 0,
	NETWORK_CODEC_DEFLATE = 1,
};
int network_block_encode(const uint8_t *input, size_t input_length, uint8_t *output,
	size_t output_capacity, size_t *output_length, uint8_t *codec);
int network_block_fragment(uint32_t stream_id, uint16_t block_id, uint32_t raw_offset,
	uint16_t raw_length, uint8_t codec, const uint8_t *encoded, size_t encoded_length,
	struct network_fragment *fragments, size_t fragment_capacity, size_t *fragment_count);
void network_stream_builder_init(struct network_stream_builder *builder, uint32_t stream_id,
	uint16_t first_block_id, uint32_t first_raw_offset);
/* Appends as much as fits; consumed reports a partial append when the block fills. */
int network_stream_builder_append(struct network_stream_builder *builder,
	const uint8_t *input, size_t input_length, uint64_t now_ms, size_t *consumed);
bool network_stream_builder_flush_due(const struct network_stream_builder *builder,
	uint64_t now_ms);
/* Returns 1 when a block is emitted, 0 when it is not due, or -errno. */
int network_stream_builder_take(struct network_stream_builder *builder, uint64_t now_ms,
	bool force, struct network_fragment *fragments, size_t fragment_capacity,
	size_t *fragment_count);
int network_fragment_pack(const struct network_fragment *fragment, uint8_t *output,
	size_t output_capacity, size_t *output_length);
int network_fragment_unpack(const uint8_t *input, size_t input_length,
	struct network_fragment *fragment);
void network_reassembler_init(struct network_reassembler *reassembler);
/* Returns 1 when a full raw block is produced, 0 while incomplete, or -errno. */
int network_reassembler_add(struct network_reassembler *reassembler, uint8_t source,
	const struct network_fragment *fragment, uint8_t *raw_output, size_t output_capacity,
	size_t *raw_length, uint32_t *raw_offset, uint32_t *received_bitmap,
	uint32_t *missing_bitmap);

#endif
