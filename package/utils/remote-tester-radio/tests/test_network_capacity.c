/* SPDX-License-Identifier: GPL-2.0-only */
/* Deterministic, single-channel shared-medium capacity exercise. */
#define _GNU_SOURCE
#include "../src/rt_network_runtime.h"
#include "../src/network/network.h"
#include "../src/host/rt_host_auth.h"
#include "../src/host/rt_host_server.h"
#include "../src/rt_ip_offload.h"
#include "../src/radio_linux.h"
#include "../src/vendor/sx126x/sx126x.h"

#include <assert.h>
#include <errno.h>
#include <json-c/json.h>
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>
#include <libubox/uloop.h>
#include <mbedtls/base64.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MEDIUM_MAX_NODES NETWORK_MAX_NODES
#define MEDIUM_MAX_ENDPOINTS (MEDIUM_MAX_NODES + 1U)
#define MEDIUM_CAPTURE_SECONDS 80U
#define MEDIUM_CAPTURE_BYTES (70U * MEDIUM_CAPTURE_SECONDS)
#define MEDIUM_LATENCY_CAPACITY (MEDIUM_MAX_NODES * MEDIUM_CAPTURE_BYTES)
#define MEDIUM_LOAD_SECONDS 60U
#define MEDIUM_DRAIN_SECONDS 12U
#define MEDIUM_STEP_US 1000ULL

struct rt_network_runtime;
struct fake_medium;

struct rt_host_server {
	rt_host_request_cb callback;
	void *context;
};
struct rt_ip_server { int unused; };
struct rt_ip_client { int unused; };

struct fake_endpoint {
	struct fake_medium *medium;
	struct rt_network_runtime *runtime;
	struct radio_config profile;
	uint8_t id;
	bool is_controller;
	bool rx_enabled;
	bool cad_pending;
	bool cad_busy;
	bool tx_active;
	bool tx_collision;
	uint64_t tx_end_us;
	uint8_t tx_packet[NETWORK_FRAME_MAX_BYTES];
	size_t tx_length;
	uint8_t rx_packet[NETWORK_FRAME_MAX_BYTES];
	size_t rx_length;
	uint64_t tx_count;
	uint64_t collision_count;
	uint64_t rx_count;
	uint64_t cad_count;
};

struct fake_medium {
	uint64_t now_us;
	uint64_t next_queue_sample_us;
	struct fake_endpoint endpoint[MEDIUM_MAX_ENDPOINTS];
	size_t endpoint_count;
	struct rt_network_runtime *controller;
	struct rt_network_runtime *nodes[MEDIUM_MAX_NODES];
	uint64_t capture_time[MEDIUM_MAX_NODES][MEDIUM_CAPTURE_BYTES];
	uint8_t delivered[MEDIUM_MAX_NODES][MEDIUM_CAPTURE_BYTES];
	size_t captured_bytes[MEDIUM_MAX_NODES];
	size_t peak_queue_bytes[MEDIUM_MAX_NODES];
	uint64_t latency_us[MEDIUM_LATENCY_CAPACITY];
	size_t latency_count;
	size_t delivered_bytes;
	size_t duplicate_bytes;
	size_t rejected_samples;
	uint64_t tx_count;
	uint64_t collision_count;
	uint64_t tx_types[NETWORK_FRAME_COMMAND_RESPONSE + 1U];
	uint64_t collision_by_type[NETWORK_FRAME_COMMAND_RESPONSE + 1U];
	uint64_t grants_by_node[MEDIUM_MAX_NODES];
	uint64_t beacon_count;
	bool incompressible;
	bool serialize_contention;
	uint8_t key[NETWORK_KEY_BYTES];
};

static struct fake_medium *active_medium;
static struct rt_host_server host_server;

int rt_host_key_load(const char *path, uint8_t key[RT_HOST_KEY_BYTES])
{ (void)path; memset(key, 0, RT_HOST_KEY_BYTES); return 0; }

struct rt_host_server *rt_host_server_start(uint16_t port, const char *uart,
	const char *key, rt_host_request_cb callback, void *context)
{
	(void)port; (void)uart; (void)key;
	host_server.callback = callback;
	host_server.context = context;
	return &host_server;
}

void rt_host_server_stop(struct rt_host_server *server)
{ (void)server; host_server.context = NULL; host_server.callback = NULL; }

static void collect_host_event(struct rt_network_runtime *runtime, const char *json)
{
	struct fake_endpoint *endpoint = NULL;
	struct json_object *root, *type, *node_id, *offset, *payload, *data;
	size_t i, raw_length, encoded_length, padding = 0;
	uint8_t id;
	if (!active_medium || !runtime || !json)
		return;
	for (i = 0; i < active_medium->endpoint_count; i++)
		if (active_medium->endpoint[i].runtime == runtime) {
			endpoint = &active_medium->endpoint[i];
			break;
		}
	if (!endpoint)
		return;
	root = json_tokener_parse(json);
	if (!root)
		return;
	if (!json_object_object_get_ex(root, "type", &type) ||
	    strcmp(json_object_get_string(type), "serial.log") ||
	    !json_object_object_get_ex(root, "nodeId", &node_id) ||
	    !json_object_object_get_ex(root, "offset", &offset) ||
	    !json_object_object_get_ex(root, "payload", &payload) ||
	    !json_object_object_get_ex(payload, "data", &data)) {
		json_object_put(root);
		return;
	}
	id = (uint8_t)json_object_get_int(node_id);
	if (id < NETWORK_FIRST_NODE_ID || id > MEDIUM_MAX_NODES) {
		json_object_put(root);
		return;
	}
	{
		const char *base64 = json_object_get_string(data);
		encoded_length = strlen(base64);
		if (encoded_length % 4U) {
			active_medium->rejected_samples++;
			json_object_put(root);
			return;
		}
		if (encoded_length && base64[encoded_length - 1U] == '=') padding++;
		if (encoded_length > 1U && base64[encoded_length - 2U] == '=') padding++;
	}
	raw_length = encoded_length / 4U * 3U - padding;
	{
		uint64_t start = json_object_get_uint64(offset);
		for (i = 0; i < raw_length; i++) {
			uint64_t byte_offset = start + i;
			size_t node_index = id - NETWORK_FIRST_NODE_ID;
			if (byte_offset >= active_medium->captured_bytes[node_index] ||
			    byte_offset >= MEDIUM_CAPTURE_BYTES ||
			    !active_medium->capture_time[node_index][byte_offset]) {
				active_medium->rejected_samples++;
				continue;
			}
			if (active_medium->delivered[node_index][byte_offset]) {
				active_medium->duplicate_bytes++;
				continue;
			}
			active_medium->delivered[node_index][byte_offset] = 1;
			active_medium->delivered_bytes++;
			if (active_medium->latency_count < MEDIUM_LATENCY_CAPACITY)
				active_medium->latency_us[active_medium->latency_count++] =
					active_medium->now_us - active_medium->capture_time[node_index][byte_offset];
		}
	}
	json_object_put(root);
}

int rt_host_server_publish(struct rt_host_server *server, const char *json)
{
	if (!server || !server->context)
		return -ENOTCONN;
	collect_host_event(server->context, json);
	return 0;
}

bool rt_host_server_has_subscriber(const struct rt_host_server *server)
{ (void)server; return true; }

struct rt_ip_server *rt_ip_server_start(uint16_t port, rt_ip_lookup_cb lookup,
	rt_ip_receive_cb receive, void *context)
{ (void)port; (void)lookup; (void)receive; (void)context; errno = ENOSYS; return NULL; }
void rt_ip_server_stop(struct rt_ip_server *server) { (void)server; }
struct rt_ip_client *rt_ip_client_start(const char *host, uint16_t port,
	const uint8_t eui[8], const uint8_t key[32], rt_ip_ack_cb ack,
	rt_ip_state_cb state, void *context)
{ (void)host; (void)port; (void)eui; (void)key; (void)ack; (void)state; (void)context; errno = ENOSYS; return NULL; }
void rt_ip_client_stop(struct rt_ip_client *client) { (void)client; }
int rt_ip_client_send(struct rt_ip_client *client, const struct rt_ip_block *block)
{ (void)client; (void)block; return -ENOSYS; }
void rt_ip_client_cancel_pending(struct rt_ip_client *client, uint32_t stream, uint16_t block)
{ (void)client; (void)stream; (void)block; }
bool rt_ip_client_healthy(const struct rt_ip_client *client) { (void)client; return false; }

int radio_linux_start_receive(struct radio_linux *radio, uint8_t length, bool continuous)
{ (void)radio; (void)length; (void)continuous; return -ENOSYS; }
int radio_linux_start_transmit(struct radio_linux *radio, const uint8_t *data, size_t length)
{ (void)radio; (void)data; (void)length; return -ENOSYS; }
int radio_linux_start_cad(struct radio_linux *radio) { (void)radio; return -ENOSYS; }
int radio_linux_cad_result(struct radio_linux *radio, bool *busy)
{ (void)radio; (void)busy; return -ENOSYS; }
int radio_linux_set_network_tx_allowed(struct radio_linux *radio, bool allowed)
{ (void)radio; (void)allowed; return 0; }

static uint64_t medium_now(void *context)
{ return ((struct fake_medium *)context)->now_us; }

static int endpoint_receive(void *context, uint8_t payload_len, bool continuous)
{
	struct fake_endpoint *endpoint = context;
	(void)payload_len; (void)continuous;
	endpoint->rx_enabled = true;
	return 0;
}

static int endpoint_transmit(void *context, const uint8_t *data, size_t length)
{
	struct fake_endpoint *endpoint = context;
	struct fake_medium *medium = endpoint->medium;
	struct network_frame peeked;
	uint32_t airtime;
	size_t i;
	if (!data || !length || length > sizeof(endpoint->tx_packet) || endpoint->tx_active)
		return -EINVAL;
	airtime = rt_network_runtime_test_airtime_us(&endpoint->profile, length);
	if (airtime == UINT32_MAX)
		return -EINVAL;
	if (network_frame_peek(data, length, &peeked))
		return -EBADMSG;
	for (i = 0; i < medium->endpoint_count; i++) {
		struct fake_endpoint *other = &medium->endpoint[i];
		if (other != endpoint && other->tx_active && other->tx_end_us > medium->now_us) {
			struct network_frame other_frame;
			other->tx_collision = true;
			endpoint->tx_collision = true;
			other->collision_count++;
			endpoint->collision_count++;
			medium->collision_count++;
			medium->collision_by_type[peeked.type]++;
			if (!network_frame_peek(other->tx_packet, other->tx_length, &other_frame) &&
			    other_frame.type <= NETWORK_FRAME_COMMAND_RESPONSE)
				medium->collision_by_type[other_frame.type]++;
		}
	}
	memcpy(endpoint->tx_packet, data, length);
	if (peeked.type <= NETWORK_FRAME_COMMAND_RESPONSE) {
		medium->tx_types[peeked.type]++;
		if (peeked.type == NETWORK_FRAME_BEACON) {
			struct network_beacon beacon;
			uint8_t grant;
			medium->beacon_count++;
			if (!network_beacon_decode(peeked.payload, peeked.payload_length, &beacon)) {
				for (grant = 0; grant < beacon.grant_count; grant++)
					if (beacon.grants[grant].node_id >= NETWORK_FIRST_NODE_ID &&
					    beacon.grants[grant].node_id <= NETWORK_MAX_ID)
						medium->grants_by_node[beacon.grants[grant].node_id - 1U]++;
			}
		}
	}
	endpoint->tx_length = length;
	endpoint->tx_end_us = medium->now_us + airtime;
	endpoint->tx_active = true;
	endpoint->rx_enabled = false;
	endpoint->tx_count++;
	medium->tx_count++;
	return 0;
}

static int endpoint_cad(void *context)
{
	struct fake_endpoint *endpoint = context;
	endpoint->cad_pending = true;
	endpoint->cad_count++;
	return 0;
}

static int endpoint_cad_result(void *context, bool *busy)
{
	struct fake_endpoint *endpoint = context;
	if (!busy)
		return -EINVAL;
	*busy = endpoint->cad_busy;
	return 0;
}

static int endpoint_get_rx(void *context, uint8_t *data, size_t capacity, size_t *length)
{
	struct fake_endpoint *endpoint = context;
	if (!endpoint->rx_length)
		return -EAGAIN;
	if (capacity < endpoint->rx_length)
		return -ENOSPC;
	memcpy(data, endpoint->rx_packet, endpoint->rx_length);
	*length = endpoint->rx_length;
	endpoint->rx_length = 0;
	return 0;
}

static const struct rt_network_phy_ops medium_phy_ops = {
	.start_receive = endpoint_receive,
	.start_transmit = endpoint_transmit,
	.start_cad = endpoint_cad,
	.cad_result = endpoint_cad_result,
	.get_rx = endpoint_get_rx,
};
static const struct rt_network_clock_ops medium_clock_ops = { .now_us = medium_now };

static uint32_t runtime_status_u32(struct rt_network_runtime *runtime, const char *name);

static int process_transmissions(struct fake_medium *medium)
{
	bool done[MEDIUM_MAX_ENDPOINTS] = { false };
	uint64_t finish = UINT64_MAX;
	size_t i, j;
	for (i = 0; i < medium->endpoint_count; i++)
		if (medium->endpoint[i].tx_active && medium->endpoint[i].tx_end_us < finish)
			finish = medium->endpoint[i].tx_end_us;
	if (finish == UINT64_MAX || finish > medium->now_us)
		return 0;
	/* The stepping loop lands exactly on the next ToA completion. */
	medium->now_us = finish;
	for (i = 0; i < medium->endpoint_count; i++)
		if (medium->endpoint[i].tx_active && medium->endpoint[i].tx_end_us == finish) {
			done[i] = true;
			medium->endpoint[i].tx_active = false;
		}
	for (i = 0; i < medium->endpoint_count; i++) {
		struct fake_endpoint *sender = &medium->endpoint[i];
		if (!done[i])
			continue;
		if (!sender->tx_collision) {
			for (j = 0; j < medium->endpoint_count; j++) {
				struct fake_endpoint *receiver = &medium->endpoint[j];
				if (j == i || receiver->tx_active || !receiver->rx_enabled)
					continue;
				memcpy(receiver->rx_packet, sender->tx_packet, sender->tx_length);
				receiver->rx_length = sender->tx_length;
				receiver->rx_count++;
				(void)rt_network_runtime_on_irq(receiver->runtime,
					SX126X_IRQ_RX_DONE, finish);
			}
		}
		memset(sender->tx_packet, 0, sender->tx_length);
		sender->tx_length = 0;
		sender->tx_collision = false;
		(void)rt_network_runtime_on_irq(sender->runtime, SX126X_IRQ_TX_DONE, finish);
	}
	return 1;
}

static int service_runtimes(struct fake_medium *medium)
{
	bool any_cad = false, channel_busy = false;
	size_t i;
	for (i = 0; i < medium->endpoint_count; i++) {
		int error = rt_network_runtime_tick(medium->endpoint[i].runtime);
		if (error)
			return error;
		any_cad |= medium->endpoint[i].cad_pending;
		channel_busy |= medium->endpoint[i].tx_active;
	}
	if (any_cad) {
		if (!medium->serialize_contention) {
			for (i = 0; i < medium->endpoint_count; i++)
				if (medium->endpoint[i].cad_pending)
					medium->endpoint[i].cad_busy = channel_busy;
		}
		for (i = 0; i < medium->endpoint_count; i++) {
			struct fake_endpoint *endpoint = &medium->endpoint[i];
			if (!endpoint->cad_pending)
				continue;
			if (medium->serialize_contention) {
				size_t j;
				endpoint->cad_busy = false;
				for (j = 0; j < medium->endpoint_count; j++)
					endpoint->cad_busy |= medium->endpoint[j].tx_active;
			}
			endpoint->cad_pending = false;
			(void)rt_network_runtime_on_irq(endpoint->runtime,
				SX126X_IRQ_CAD_DONE, medium->now_us);
		}
	}
	if (medium->now_us >= medium->next_queue_sample_us) {
		for (i = 1; i < medium->endpoint_count; i++) {
			size_t node_index = medium->endpoint[i].id - NETWORK_FIRST_NODE_ID;
			size_t queue_bytes = runtime_status_u32(medium->endpoint[i].runtime,
				"network_queue_bytes");
			if (queue_bytes > medium->peak_queue_bytes[node_index])
				medium->peak_queue_bytes[node_index] = queue_bytes;
		}
		medium->next_queue_sample_us = medium->now_us + 100000U;
	}
	return 0;
}

static uint8_t capture_noise(uint8_t node_id, size_t offset)
{
	uint32_t x = (uint32_t)(node_id * 0x9e3779b9U) ^
		(uint32_t)(offset + 1U) * 0x85ebca6bU;
	x ^= x >> 16; x *= 0x7feb352dU; x ^= x >> 15;
	return (uint8_t)(x ^ (x >> 8) ^ (x >> 16));
}

static void make_capture_chunk(uint8_t bytes[70], uint8_t node_id, size_t start,
	uint64_t second, bool incompressible)
{
	static const uint8_t prefix[] = "2026-09-26 12:34:56 ";
	static const uint8_t tail[] = " status=OK\r\n........";
	size_t j;
	for (j = 0; j < 70U; j++) {
		if (!incompressible && j < 10U)
			bytes[j] = prefix[j];
		else if (!incompressible && j >= 50U)
			bytes[j] = tail[(j - 50U) % (sizeof(tail) - 1U)];
		else
			bytes[j] = capture_noise(node_id, start + j + second * 17U);
	}
}

static void capture_second(struct fake_medium *medium, uint64_t second)
{
	size_t i;
	for (i = 0; i < medium->endpoint_count; i++) {
		struct fake_endpoint *endpoint = &medium->endpoint[i];
		uint8_t bytes[70];
		size_t start, j;
		if (endpoint->is_controller)
			continue;
		start = medium->captured_bytes[endpoint->id - NETWORK_FIRST_NODE_ID];
		assert(start + sizeof(bytes) <= MEDIUM_CAPTURE_BYTES);
		make_capture_chunk(bytes, endpoint->id, start, second, medium->incompressible);
		for (j = 0; j < sizeof(bytes); j++) {
			medium->capture_time[endpoint->id - NETWORK_FIRST_NODE_ID][start + j] =
				second * 1000000ULL;
		}
		assert(rt_network_runtime_capture(endpoint->runtime, bytes, sizeof(bytes)) == 0);
		medium->captured_bytes[endpoint->id - NETWORK_FIRST_NODE_ID] += sizeof(bytes);
	}
}

static int simulate_until(struct fake_medium *medium, uint64_t deadline_us,
	uint64_t *next_capture_us, bool generate_logs)
{
	int guard = 0;
	while (medium->now_us < deadline_us) {
		uint64_t next_us = medium->now_us + MEDIUM_STEP_US;
		size_t i;
		int progress;
		do {
			progress = process_transmissions(medium);
			if (progress < 0)
				return progress;
			if (progress && service_runtimes(medium))
				return -EIO;
		} while (progress);
		if (service_runtimes(medium))
			return -EIO;
		if (generate_logs && *next_capture_us <= medium->now_us) {
			capture_second(medium, *next_capture_us / 1000000ULL);
			*next_capture_us += 1000000ULL;
		}
		if (generate_logs && *next_capture_us < next_us)
			next_us = *next_capture_us;
		if (next_us > deadline_us)
			next_us = deadline_us;
		for (i = 0; i < medium->endpoint_count; i++)
			if (medium->endpoint[i].tx_active && medium->endpoint[i].tx_end_us < next_us)
				next_us = medium->endpoint[i].tx_end_us;
		if (next_us <= medium->now_us)
			next_us = medium->now_us + 1U;
		medium->now_us = next_us;
		if (++guard > 10000000)
			return -ELOOP;
	}
	return 0;
}

static bool runtime_joined(struct rt_network_runtime *runtime)
{
	static const struct blobmsg_policy policy[] = {
		{ .name = "network_joined", .type = BLOBMSG_TYPE_INT8 },
	};
	struct blob_buf status = {};
	struct blob_attr *fields[1] = {};
	bool joined;
	blob_buf_init(&status, 0);
	rt_network_runtime_add_status(runtime, &status);
	blobmsg_parse(policy, 1, fields, blobmsg_data(status.head), blobmsg_len(status.head));
	joined = fields[0] && blobmsg_get_u8(fields[0]);
	blob_buf_free(&status);
	return joined;
}

static uint32_t runtime_status_u32(struct rt_network_runtime *runtime, const char *name)
{
	const struct blobmsg_policy policy[] = {
		{ .name = "network_frame", .type = BLOBMSG_TYPE_INT32 },
		{ .name = "network_last_error", .type = BLOBMSG_TYPE_INT32 },
		{ .name = "network_requested_airtime_us", .type = BLOBMSG_TYPE_INT32 },
		{ .name = "network_queue_bytes", .type = BLOBMSG_TYPE_INT32 },
		{ .name = "network_serial_buffered", .type = BLOBMSG_TYPE_INT32 },
		{ .name = "network_tx_block_active", .type = BLOBMSG_TYPE_INT8 },
		{ .name = "network_tx_ack_bitmap", .type = BLOBMSG_TYPE_INT32 },
		{ .name = "network_gap_pending", .type = BLOBMSG_TYPE_INT8 },
	};
	struct blob_buf status = {};
	struct blob_attr *fields[sizeof(policy) / sizeof(policy[0])] = {};
	uint32_t value = 0;
	size_t i;
	blob_buf_init(&status, 0);
	rt_network_runtime_add_status(runtime, &status);
	blobmsg_parse(policy, sizeof(policy) / sizeof(policy[0]), fields,
		blobmsg_data(status.head), blobmsg_len(status.head));
	for (i = 0; i < sizeof(policy) / sizeof(policy[0]); i++)
		if (!strcmp(name, policy[i].name) && fields[i]) {
			value = policy[i].type == BLOBMSG_TYPE_INT8 ?
				blobmsg_get_u8(fields[i]) : blobmsg_get_u32(fields[i]);
			break;
		}
	blob_buf_free(&status);
	return value;
}

static int compare_u64(const void *left, const void *right)
{
	uint64_t a = *(const uint64_t *)left, b = *(const uint64_t *)right;
	return a < b ? -1 : a > b ? 1 : 0;
}

static void report_workload_ratios(void)
{
	uint8_t raw[280], encoded[NETWORK_MAX_COMPRESSED_BLOCK], codec;
	size_t encoded_length;
	bool overload;
	size_t block_sizes[] = { 210U, 280U };
	size_t b;
	for (overload = false; ; overload = true) {
		for (b = 0; b < sizeof(block_sizes) / sizeof(block_sizes[0]); b++) {
			unsigned second, seconds = (unsigned)(block_sizes[b] / 70U);
			for (second = 1; second <= seconds; second++)
				make_capture_chunk(raw + (second - 1U) * 70U, 1,
					(second - 1U) * 70U, second, overload);
			assert(network_block_encode(raw, block_sizes[b], encoded, sizeof(encoded),
				&encoded_length, &codec) == 0);
			printf("workload=%s block_bytes=%zu encoded_bytes=%zu fragments=%zu ratio=%.3f\n",
				overload ? "incompressible-overload" : "formatted-normal",
				block_sizes[b], encoded_length,
				(encoded_length + NETWORK_FRAGMENT_DATA_BYTES - 1U) /
					NETWORK_FRAGMENT_DATA_BYTES,
				(double)encoded_length / block_sizes[b]);
		}
		if (overload)
			break;
	}
}

static int run_capacity_case(size_t node_count, bool incompressible,
	bool serialize_contention)
{
	static const uint8_t beacon_key[NETWORK_KEY_BYTES] = {
		0x31,0x28,0x67,0x9a,0x04,0x55,0x13,0xa2,0x80,0x9d,0xfe,0x10,0x64,0x81,0x32,0xb7,
		0x99,0x20,0x42,0x63,0x52,0xa8,0x11,0x90,0xee,0x72,0x04,0x18,0x2a,0xc1,0x54,0x01
	};
	struct fake_medium *medium = calloc(1, sizeof(*medium));
	struct rt_network_test_peer peers[MEDIUM_MAX_NODES] = { 0 };
	struct rt_network_runtime *runtimes[MEDIUM_MAX_ENDPOINTS] = { 0 };
	struct radio_config profile = { .frequency_mhz = 433, .bandwidth_khz = 500,
		.spreading_factor = 7, .coding_rate = 5, .sync_word = 0x1424,
		.spi_hz = 2000000 };
	char eui_text[MEDIUM_MAX_NODES][17];
	struct rt_network_config config = { 0 };
	uint64_t start_us, join_done_us = 0, next_capture_us;
	size_t i, delivered_expected = 0, received_count;
	int result;
	assert(medium && node_count >= 1U && node_count <= MEDIUM_MAX_NODES);
	medium->now_us = 1000U;
	medium->next_queue_sample_us = 100000U;
	medium->endpoint_count = node_count + 1U;
	medium->incompressible = incompressible;
	medium->serialize_contention = serialize_contention;
	medium->key[0] = 0x41;
	memcpy(medium->key, beacon_key, sizeof(beacon_key));
	active_medium = medium;
	for (i = 0; i < node_count; i++) {
		size_t j;
		uint8_t id = (uint8_t)(i + NETWORK_FIRST_NODE_ID);
		peers[i].eui[0] = 2U;
		peers[i].eui[6] = 0x50U;
		peers[i].eui[7] = id;
		for (j = 0; j < sizeof(peers[i].psk); j++)
			peers[i].psk[j] = (uint8_t)(0x20U + id * 7U + j * 13U);
		snprintf(eui_text[i], sizeof(eui_text[i]), "020000000000%02x%02x", 0x50U, id);
	}
	assert(uloop_init() == 0);
	medium->endpoint[0] = (struct fake_endpoint) { .medium = medium, .profile = profile,
		.id = NETWORK_CONTROLLER_ID, .is_controller = true };
	config.role = RT_NETWORK_CONTROLLER;
	config.network_id = 77;
	config.host_port = 45671;
	config.host_psk_path = "fake-host-key";
	config.queue_bytes = 128U * 1024U;
	config.airtime_budget_us = 3450000U;
	config.radio_profile = profile;
	config.transmit_enabled = true;
	config.phy_ops = &medium_phy_ops;
	config.clock_ops = &medium_clock_ops;
	config.io_context = &medium->endpoint[0];
	config.clock_context = medium;
	config.test_beacon_key = beacon_key;
	config.test_registry = peers;
	config.test_registry_count = node_count;
	config.test_boot_nonce = 0xabc0000000000001ULL;
	result = rt_network_runtime_start(&runtimes[0], &config);
	if (result) {
		fprintf(stderr, "controller start failed: %d\n", result);
		abort();
	}
	medium->endpoint[0].runtime = runtimes[0];
	medium->controller = runtimes[0];
	for (i = 0; i < node_count; i++) {
		uint8_t id = (uint8_t)(i + NETWORK_FIRST_NODE_ID);
		struct fake_endpoint *endpoint = &medium->endpoint[i + 1U];
		*endpoint = (struct fake_endpoint) { .medium = medium, .profile = profile, .id = id };
		config.role = RT_NETWORK_NODE;
		config.host_port = 0;
		config.host_psk_path = NULL;
		config.node_eui = eui_text[i];
		config.io_context = endpoint;
		config.test_node_key = peers[i].psk;
		config.test_registry = NULL;
		config.test_registry_count = 0;
		config.test_boot_nonce = 0x1000000000000000ULL + id;
		result = rt_network_runtime_start(&runtimes[i + 1U], &config);
		if (result) {
			fprintf(stderr, "node %u start failed: %d\n", id, result);
			abort();
		}
		endpoint->runtime = runtimes[i + 1U];
		medium->nodes[i] = runtimes[i + 1U];
	}
	start_us = medium->now_us;
	for (i = 0; i < 60000U; i++) {
		bool all_joined = true;
		for (size_t j = 0; j < node_count; j++)
			all_joined &= runtime_joined(runtimes[j + 1U]);
		if (all_joined) {
			join_done_us = medium->now_us;
			break;
		}
		result = simulate_until(medium, medium->now_us + MEDIUM_STEP_US, NULL, false);
		if (result) {
			fprintf(stderr, "simulation error nodes=%zu now_us=%llu result=%d tx=%llu collisions=%llu\n",
				node_count, (unsigned long long)medium->now_us, result,
				(unsigned long long)medium->tx_count,
				(unsigned long long)medium->collision_count);
			abort();
		}
	}
	if (!join_done_us) {
		fprintf(stderr, "join timeout nodes=%zu now_ms=%llu tx=%llu collisions=%llu\n",
			node_count, (unsigned long long)(medium->now_us / 1000U),
			(unsigned long long)medium->tx_count,
			(unsigned long long)medium->collision_count);
		for (i = 1; i <= node_count; i++)
			fprintf(stderr, " node=%zu joined=%d cad=%llu tx=%llu rx=%llu coll=%llu\n",
				i, runtime_joined(runtimes[i]),
				(unsigned long long)medium->endpoint[i].cad_count,
				(unsigned long long)medium->endpoint[i].tx_count,
				(unsigned long long)medium->endpoint[i].rx_count,
				(unsigned long long)medium->endpoint[i].collision_count);
		abort();
	}
	next_capture_us = ((medium->now_us / 1000000ULL) + 1U) * 1000000ULL;
	result = simulate_until(medium, next_capture_us, &next_capture_us, true);
	assert(result == 0);
	result = simulate_until(medium, next_capture_us +
		(uint64_t)MEDIUM_LOAD_SECONDS * 1000000ULL, &next_capture_us, true);
	assert(result == 0);
	for (i = 0; i < node_count; i++)
		delivered_expected += medium->captured_bytes[i];
	result = simulate_until(medium, medium->now_us +
		(uint64_t)MEDIUM_DRAIN_SECONDS * 1000000ULL, &next_capture_us, false);
	assert(result == 0);
	received_count = medium->delivered_bytes;
	if (received_count != delivered_expected) {
		fprintf(stderr, "delivery incomplete nodes=%zu workload=%s/%s now_s=%.3f tx=%llu collisions=%llu "
			"delivered=%zu expected=%zu\n", node_count,
			incompressible ? "incompressible" : "formatted",
			serialize_contention ? "serial-CAD" : "normal-CAD",
			(double)medium->now_us / 1000000.0,
			(unsigned long long)medium->tx_count,
			(unsigned long long)medium->collision_count, received_count, delivered_expected);
	}
	assert(medium->rejected_samples == 0);
	assert(medium->latency_count == received_count);
	qsort(medium->latency_us, medium->latency_count, sizeof(medium->latency_us[0]), compare_u64);
	{
		size_t p95_index = (medium->latency_count * 95U + 99U) / 100U - 1U;
		uint64_t p95_ms = medium->latency_us[p95_index] / 1000U;
		size_t pending = delivered_expected - received_count;
		uint64_t oldest_pending_ms = 0;
		uint32_t nodes_with_gap = 0;
		size_t queue_now = 0, queue_peak = 0;
		uint64_t grant_total = 0;
		for (i = 0; i < node_count; i++) {
			size_t j;
			queue_now += runtime_status_u32(runtimes[i + 1U], "network_queue_bytes");
			queue_peak += medium->peak_queue_bytes[i];
			grant_total += medium->grants_by_node[i];
			nodes_with_gap += runtime_status_u32(runtimes[i + 1U], "network_gap_pending") != 0;
			for (j = 0; j < medium->captured_bytes[i]; j++)
				if (!medium->delivered[i][j]) {
					uint64_t age = (medium->now_us - medium->capture_time[i][j]) / 1000U;
					if (age > oldest_pending_ms)
						oldest_pending_ms = age;
				}
		}
		printf("nodes=%zu workload=%s/%s join_s=%.3f steady_capture_s=%u drain_s=%u "
			"delivered=%zu captured=%zu pending=%zu queue_now=%zu queue_peak_sum=%zu "
			"p95_ms=%llu oldest_pending_ms=%llu gaps=%u grants/frame=%.2f collisions=%llu "
			"coll_join=%llu coll_slot=%llu coll_data=%llu tx=%llu data_tx=%llu "
			"slot_req=%llu duplicate=%zu\n",
		node_count, incompressible ? "incompressible-overload" : "formatted-normal",
		serialize_contention ? "serial-CAD" : "shared-CAD",
			(double)(join_done_us - start_us) / 1000000.0,
			MEDIUM_LOAD_SECONDS, MEDIUM_DRAIN_SECONDS, received_count,
			delivered_expected, pending, queue_now, queue_peak,
			(unsigned long long)p95_ms,
			(unsigned long long)oldest_pending_ms, nodes_with_gap,
			(double)grant_total / medium->beacon_count,
			(unsigned long long)medium->collision_count,
			(unsigned long long)medium->collision_by_type[NETWORK_FRAME_JOIN],
			(unsigned long long)medium->collision_by_type[NETWORK_FRAME_SLOT_REQUEST],
			(unsigned long long)medium->collision_by_type[NETWORK_FRAME_DATA],
			(unsigned long long)medium->tx_count,
			(unsigned long long)medium->tx_types[NETWORK_FRAME_DATA],
			(unsigned long long)medium->tx_types[NETWORK_FRAME_SLOT_REQUEST],
			medium->duplicate_bytes);
		if (!incompressible && (pending || p95_ms > 10000U)) {
			fprintf(stderr, "capacity target failed: %zu nodes p95=%llu ms > 10000 ms\n",
				node_count, (unsigned long long)p95_ms);
			result = -ERANGE;
		}
	}
	for (i = 0; i < medium->endpoint_count; i++)
		rt_network_runtime_stop(runtimes[i]);
	uloop_done();
	active_medium = NULL;
	free(medium);
	return result;
}

int main(void)
{
	int failed = 0;
	report_workload_ratios();
	failed |= run_capacity_case(3, false, false) != 0;
	failed |= run_capacity_case(8, false, false) != 0;
	failed |= run_capacity_case(8, true, false) != 0;
	failed |= run_capacity_case(3, false, true) != 0;
	failed |= run_capacity_case(8, false, true) != 0;
	return failed ? 1 : 0;
}
