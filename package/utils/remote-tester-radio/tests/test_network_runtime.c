/* SPDX-License-Identifier: GPL-2.0-only */
#define _GNU_SOURCE
#include "../src/rt_network_runtime.h"
#include "../src/network/network.h"
#include "../src/host/rt_host_auth.h"
#include "../src/host/rt_host_server.h"
#include "../src/radio_linux.h"
#include "../src/rt_ip_offload.h"
#include "../src/rt_command.h"
#include "../src/vendor/sx126x/sx126x.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>
#include <libubox/uloop.h>
#include <mbedtls/base64.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#ifdef __APPLE__
#include <util.h>
#else
#include <pty.h>
#endif

struct rt_host_server { int unused; };
struct rt_ip_server { int unused; };
struct rt_ip_client { int unused; };
struct fake_host_registration {
	struct rt_host_server server;
	rt_host_request_cb callback;
	void *context;
};
static struct fake_host_registration fake_hosts[4];
static size_t fake_host_count;
static bool fake_host_publish_success;
static char fake_host_last_event[2048];

/* Runtime-only shims: this fake-PHY test does not open host sockets or a tty. */
int rt_host_key_load(const char *path, uint8_t key[RT_HOST_KEY_BYTES])
{ (void)path; memset(key, 0, RT_HOST_KEY_BYTES); return 0; }
struct rt_host_server *rt_host_server_start(uint16_t port, const char *uart,
    const char *key, rt_host_request_cb cb, void *context)
{
	struct fake_host_registration *registration;
	(void)port; (void)uart; (void)key;
	assert(fake_host_count < sizeof(fake_hosts) / sizeof(fake_hosts[0]));
	registration = &fake_hosts[fake_host_count++];
	registration->callback = cb;
	registration->context = context;
	return &registration->server;
}
void rt_host_server_stop(struct rt_host_server *server) { (void)server; }
int rt_host_server_publish(struct rt_host_server *server, const char *json)
{
	(void)server;
	if (json)
		snprintf(fake_host_last_event, sizeof(fake_host_last_event), "%s", json);
	return fake_host_publish_success ? 0 : -ENOTCONN;
}
bool rt_host_server_has_subscriber(const struct rt_host_server *server)
{ (void)server; return false; }
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

struct fake_clock { uint64_t now_us; };
struct fake_phy {
	uint8_t tx[NETWORK_FRAME_MAX_BYTES];
	size_t tx_length;
	uint8_t rx[NETWORK_FRAME_MAX_BYTES];
	size_t rx_length;
	unsigned int cad_count;
	bool cad_busy;
};

static uint64_t fake_now(void *context)
{ return ((struct fake_clock *)context)->now_us; }

static int fake_rx(void *context, uint8_t payload_len, bool continuous)
{ (void)context; (void)payload_len; (void)continuous; return 0; }

static int fake_tx(void *context, const uint8_t *bytes, size_t length)
{
	struct fake_phy *phy = context;
	if (phy->tx_length || !length || length > sizeof(phy->tx)) return -EBUSY;
	memcpy(phy->tx, bytes, length);
	phy->tx_length = length;
	return 0;
}

static int fake_cad(void *context)
{ ((struct fake_phy *)context)->cad_count++; return 0; }

static int fake_cad_result(void *context, bool *busy)
{ *busy = ((struct fake_phy *)context)->cad_busy; return 0; }

static int fake_get_rx(void *context, uint8_t *bytes, size_t capacity, size_t *length)
{
	struct fake_phy *phy = context;
	if (!phy->rx_length) return -EAGAIN;
	if (capacity < phy->rx_length) return -ENOSPC;
	memcpy(bytes, phy->rx, phy->rx_length);
	*length = phy->rx_length;
	phy->rx_length = 0;
	return 0;
}

static const struct rt_network_phy_ops fake_ops = {
	.start_receive = fake_rx, .start_transmit = fake_tx, .start_cad = fake_cad,
	.cad_result = fake_cad_result, .get_rx = fake_get_rx,
};
static const struct rt_network_clock_ops fake_clock_ops = { .now_us = fake_now };

static void inject_tx(struct rt_network_runtime *source_runtime, struct fake_phy *source_phy,
	struct rt_network_runtime *destination_runtime, struct fake_phy *destination_phy,
	struct fake_clock *clock, uint16_t irq)
{
	uint8_t packet[NETWORK_FRAME_MAX_BYTES];
	size_t length = source_phy->tx_length;
	assert(source_phy->tx_length > 0);
	memcpy(packet, source_phy->tx, length);
	source_phy->tx_length = 0;
	assert(rt_network_runtime_on_irq(source_runtime, SX126X_IRQ_TX_DONE,
		clock->now_us) == 0);
	memcpy(destination_phy->rx, packet, length);
	destination_phy->rx_length = length;
	assert(rt_network_runtime_on_irq(destination_runtime, irq, clock->now_us) == 0);
	memset(packet, 0, sizeof(packet));
}

static void discard_tx(struct rt_network_runtime *source_runtime, struct fake_phy *source_phy,
	struct fake_clock *clock)
{
	assert(source_phy->tx_length > 0);
	source_phy->tx_length = 0;
	assert(rt_network_runtime_on_irq(source_runtime, SX126X_IRQ_TX_DONE,
		clock->now_us) == 0);
}

enum { STATUS_JOINED, STATUS_BLOCK_ACTIVE, STATUS_QUEUE_BYTES, STATUS_BOOT,
	STATUS_CONTROLLER_BOOT, STATUS_TX_SEQUENCE, STATUS_LAST_ERROR, STATUS_GAP_PENDING,
	STATUS_GAP_BEFORE_QUEUE, STATUS_GAP_REASON, STATUS_GAP_FROM, STATUS_GAP_TO,
	STATUS_SERIAL_BUFFERED, STATUS_GAP_IN_FLIGHT, STATUS_NEXT_GAP_PENDING,
	STATUS_NEXT_GAP_FROM, STATUS_NEXT_GAP_TO, STATUS_RAW_OFFSET,
	STATUS_BEACON_REPLAY_NONCE, STATUS_FRAME, __STATUS_MAX };
static const struct blobmsg_policy status_policy[__STATUS_MAX] = {
	[STATUS_JOINED] = { .name = "network_joined", .type = BLOBMSG_TYPE_INT8 },
	[STATUS_BLOCK_ACTIVE] = { .name = "network_tx_block_active", .type = BLOBMSG_TYPE_INT8 },
	[STATUS_QUEUE_BYTES] = { .name = "network_queue_bytes", .type = BLOBMSG_TYPE_INT32 },
	[STATUS_BOOT] = { .name = "network_boot_nonce", .type = BLOBMSG_TYPE_INT64 },
	[STATUS_CONTROLLER_BOOT] = { .name = "network_controller_boot_nonce", .type = BLOBMSG_TYPE_INT64 },
	[STATUS_TX_SEQUENCE] = { .name = "network_tx_sequence", .type = BLOBMSG_TYPE_INT32 },
	[STATUS_LAST_ERROR] = { .name = "network_last_error", .type = BLOBMSG_TYPE_INT32 },
	[STATUS_GAP_PENDING] = { .name = "network_gap_pending", .type = BLOBMSG_TYPE_INT8 },
	[STATUS_GAP_BEFORE_QUEUE] = { .name = "network_gap_before_queue", .type = BLOBMSG_TYPE_INT8 },
	[STATUS_GAP_REASON] = { .name = "network_gap_reason", .type = BLOBMSG_TYPE_INT32 },
	[STATUS_GAP_FROM] = { .name = "network_gap_from", .type = BLOBMSG_TYPE_INT32 },
	[STATUS_GAP_TO] = { .name = "network_gap_to", .type = BLOBMSG_TYPE_INT32 },
	[STATUS_SERIAL_BUFFERED] = { .name = "network_serial_buffered", .type = BLOBMSG_TYPE_INT32 },
	[STATUS_GAP_IN_FLIGHT] = { .name = "network_gap_in_flight", .type = BLOBMSG_TYPE_INT8 },
	[STATUS_NEXT_GAP_PENDING] = { .name = "network_next_gap_pending", .type = BLOBMSG_TYPE_INT8 },
	[STATUS_NEXT_GAP_FROM] = { .name = "network_next_gap_from", .type = BLOBMSG_TYPE_INT32 },
	[STATUS_NEXT_GAP_TO] = { .name = "network_next_gap_to", .type = BLOBMSG_TYPE_INT32 },
	[STATUS_RAW_OFFSET] = { .name = "network_raw_offset", .type = BLOBMSG_TYPE_INT32 },
	[STATUS_BEACON_REPLAY_NONCE] = { .name = "network_beacon_replay_controller_nonce", .type = BLOBMSG_TYPE_INT64 },
	[STATUS_FRAME] = { .name = "network_frame", .type = BLOBMSG_TYPE_INT32 },
};

enum { HOST_ACCEPTED, HOST_PENDING, HOST_STATUS, HOST_WRITTEN, __HOST_RESULT_MAX };
static const struct blobmsg_policy host_result_policy[__HOST_RESULT_MAX] = {
	[HOST_ACCEPTED] = { .name = "accepted", .type = BLOBMSG_TYPE_INT8 },
	[HOST_PENDING] = { .name = "pending", .type = BLOBMSG_TYPE_INT8 },
	[HOST_STATUS] = { .name = "status", .type = BLOBMSG_TYPE_INT32 },
	[HOST_WRITTEN] = { .name = "written", .type = BLOBMSG_TYPE_INT32 },
};

static uint64_t status_u64(struct rt_network_runtime *runtime, const char *name)
{
	struct blob_buf status = {};
	struct blob_attr *fields[__STATUS_MAX] = {};
	uint64_t value;
	blob_buf_init(&status, 0);
	rt_network_runtime_add_status(runtime, &status);
	blobmsg_parse(status_policy, __STATUS_MAX, fields,
		blobmsg_data(status.head), blobmsg_len(status.head));
	if (!strcmp(name, "network_boot_nonce"))
		value = fields[STATUS_BOOT] ? blobmsg_get_u64(fields[STATUS_BOOT]) : 0;
	else if (!strcmp(name, "network_controller_boot_nonce"))
		value = fields[STATUS_CONTROLLER_BOOT] ?
			blobmsg_get_u64(fields[STATUS_CONTROLLER_BOOT]) : 0;
	else if (!strcmp(name, "network_beacon_replay_controller_nonce"))
		value = fields[STATUS_BEACON_REPLAY_NONCE] ?
			blobmsg_get_u64(fields[STATUS_BEACON_REPLAY_NONCE]) : 0;
	else
		value = fields[STATUS_TX_SEQUENCE] ?
			blobmsg_get_u32(fields[STATUS_TX_SEQUENCE]) : 0;
	blob_buf_free(&status);
	return value;
}

static uint32_t status_u32(struct rt_network_runtime *runtime, const char *name)
{
	struct blob_buf status = {};
	struct blob_attr *fields[__STATUS_MAX] = {};
	uint32_t value;
	blob_buf_init(&status, 0);
	rt_network_runtime_add_status(runtime, &status);
	blobmsg_parse(status_policy, __STATUS_MAX, fields,
		blobmsg_data(status.head), blobmsg_len(status.head));
	{
		int index = !strcmp(name, "network_last_error") ? STATUS_LAST_ERROR :
			!strcmp(name, "network_raw_offset") ? STATUS_RAW_OFFSET :
			!strcmp(name, "network_frame") ? STATUS_FRAME : STATUS_TX_SEQUENCE;
		value = fields[index] ? blobmsg_get_u32(fields[index]) : 0;
	}
	blob_buf_free(&status);
	return value;
}

static struct fake_host_registration *host_for_context(void *context)
{
	size_t i;
	for (i = 0; i < fake_host_count; i++)
		if (fake_hosts[i].context == context)
			return &fake_hosts[i];
	return NULL;
}

static void test_node_host_service_is_controller_only(void)
{
	static const uint8_t key[32] = { 0x41 };
	struct fake_clock clock = { .now_us = 1 };
	struct fake_phy phy = { 0 };
	struct rt_network_runtime *node = NULL;
	struct rt_network_config config = { 0 };
	size_t host_count = fake_host_count;
	assert(uloop_init() == 0);
	config.role = RT_NETWORK_NODE;
	config.network_id = 77;
	config.node_eui = "02123456789abcde";
	config.queue_bytes = 65536;
	config.radio_profile = (struct radio_config) { .frequency_mhz = 433,
		.bandwidth_khz = 500, .spreading_factor = 7, .coding_rate = 5,
		.sync_word = 0x1424, .spi_hz = 2000000 };
	config.phy_ops = &fake_ops;
	config.clock_ops = &fake_clock_ops;
	config.io_context = &phy;
	config.clock_context = &clock;
	config.test_beacon_key = key;
	config.test_node_key = key;
	config.host_port = 45671;
	config.host_uart_path = "/dev/ttyS1";
	config.host_psk_path = "host-key-must-not-be-opened";
	assert(rt_network_runtime_start(&node, &config) == 0);
	assert(fake_host_count == host_count);
	rt_network_runtime_stop(node);

	/* Node provisioning has no host PSK requirement. */
	node = NULL;
	config.host_psk_path = NULL;
	assert(rt_network_runtime_start(&node, &config) == 0);
	assert(fake_host_count == host_count);
	rt_network_runtime_stop(node);
	uloop_done();
}

static void test_iperf_busy_start_keeps_active_and_completion_uuid(void)
{
	static const uint8_t key[32] = { 0x42 };
	struct fake_clock clock = { .now_us = 1 };
	struct fake_phy phy = { 0 };
	struct rt_network_runtime *node = NULL;
	struct rt_network_config config = { 0 };
	struct rt_command command_a = { .kind = RT_COMMAND_IPERF_START,
		.data_length = RT_COMMAND_UUID_BYTES };
	struct rt_command command_b;
	struct rt_command_result result = { .kind = RT_COMMAND_IPERF_START };
	uint8_t active_uuid[RT_COMMAND_UUID_BYTES], event_uuid[RT_COMMAND_UUID_BYTES];
	bool event_pending;

	assert(uloop_init() == 0);
	config.role = RT_NETWORK_NODE;
	config.network_id = 77;
	config.node_eui = "02123456789abcde";
	config.queue_bytes = 65536;
	config.radio_profile = (struct radio_config) { .frequency_mhz = 433,
		.bandwidth_khz = 500, .spreading_factor = 7, .coding_rate = 5,
		.sync_word = 0x1424, .spi_hz = 2000000 };
	config.phy_ops = &fake_ops;
	config.clock_ops = &fake_clock_ops;
	config.io_context = &phy;
	config.clock_context = &clock;
	config.test_beacon_key = key;
	config.test_node_key = key;
	assert(rt_network_runtime_start(&node, &config) == 0);
	for (size_t i = 0; i < RT_COMMAND_UUID_BYTES; i++) {
		command_a.data[i] = (uint8_t)(0xa0U + i);
	}
	command_b = command_a;
	for (size_t i = 0; i < RT_COMMAND_UUID_BYTES; i++)
		command_b.data[i] = (uint8_t)(0xb0U + i);
	memcpy(result.request_uuid, command_a.data, RT_COMMAND_UUID_BYTES);
	assert(rt_network_runtime_test_record_iperf_start(node, &command_a, &result) == 0);
	result.status = EBUSY;
	assert(rt_network_runtime_test_record_iperf_start(node, &command_b, &result) == 0);
	assert(rt_network_runtime_test_iperf_complete(node, command_a.data, 0) == 0);
	assert(rt_network_runtime_test_iperf_state(node, active_uuid, event_uuid,
		&event_pending) == 0);
	assert(!memcmp(active_uuid, command_a.data, RT_COMMAND_UUID_BYTES));
	assert(!memcmp(event_uuid, command_a.data, RT_COMMAND_UUID_BYTES));
	assert(event_pending);
	rt_network_runtime_stop(node);
	uloop_done();
}

static void assert_status(struct rt_network_runtime *runtime, bool joined,
	bool block_active, uint32_t min_queue_bytes)
{
	struct blob_buf status = {};
	struct blob_attr *fields[__STATUS_MAX] = {};
	blob_buf_init(&status, 0);
	rt_network_runtime_add_status(runtime, &status);
	blobmsg_parse(status_policy, __STATUS_MAX, fields,
		blobmsg_data(status.head), blobmsg_len(status.head));
	assert(fields[STATUS_JOINED] && !!blobmsg_get_u8(fields[STATUS_JOINED]) == joined);
	assert(fields[STATUS_BLOCK_ACTIVE] &&
		!!blobmsg_get_u8(fields[STATUS_BLOCK_ACTIVE]) == block_active);
	assert(fields[STATUS_QUEUE_BYTES] &&
		blobmsg_get_u32(fields[STATUS_QUEUE_BYTES]) >= min_queue_bytes);
	blob_buf_free(&status);
}

static uint32_t radio_airtime_test_us(const struct radio_config *profile, size_t length)
{
	uint64_t bits, denominator, symbols, symbol_x4, bandwidth_hz;
	uint32_t sf = profile->spreading_factor;
	uint32_t de = radio_ldro_required(sf, profile->bandwidth_khz) ? 1U : 0U;
	bandwidth_hz = (uint64_t)profile->bandwidth_khz * 1000U;
	bits = 8U * length - 4U * sf + 28U + 16U;
	denominator = 4U * (sf - 2U * de);
	symbols = 8U + ((bits + denominator - 1U) / denominator) * profile->coding_rate;
	symbol_x4 = 4U * (8U + symbols) + 17U;
	return (uint32_t)((((1ULL << sf) * 1000000ULL * symbol_x4) +
		bandwidth_hz * 4U - 1U) / (bandwidth_hz * 4U));
}

static void test_late_join_does_not_overlap_beacon(void)
{
	static const uint8_t beacon_key[32] = {
		0x31,0x28,0x67,0x9a,0x04,0x55,0x13,0xa2,0x80,0x9d,0xfe,0x10,0x64,0x81,0x32,0xb7,
		0x99,0x20,0x42,0x63,0x52,0xa8,0x11,0x90,0xee,0x72,0x04,0x18,0x2a,0xc1,0x54,0x01
	};
	static const uint8_t node_key[32] = {
		0x87,0x66,0x55,0x44,0x33,0x22,0x11,0x00,0x3a,0x4b,0x5c,0x6d,0x7e,0x8f,0x90,0xa1,
		0x12,0x23,0x34,0x45,0x56,0x67,0x78,0x89,0x9a,0xab,0xbc,0xcd,0xde,0xef,0xf0,0x01
	};
	const char eui[] = "02123456789abcde";
	struct fake_clock clock = { .now_us = 1 };
	struct fake_phy phy = { 0 };
	struct rt_network_runtime *node = NULL;
	struct rt_network_config config = { 0 };
	struct network_beacon beacon = { .frame_number = 1,
		.contention_ms = NETWORK_CONTENTION_MS,
		.downlink_ms = NETWORK_DEFAULT_DOWNLINK_MS };
	struct network_frame frame = { 0 };
	uint8_t beacon_payload[NETWORK_FRAME_MAX_PAYLOAD], wire[NETWORK_FRAME_MAX_BYTES];
	size_t beacon_length, wire_length;
	uint64_t controller_nonce = 0x1020304050607080ULL;
	uint32_t airtime_us;
	assert(uloop_init() == 0);
	config.role = RT_NETWORK_NODE;
	config.network_id = 77;
	config.node_eui = eui;
	config.queue_bytes = 65536;
	config.radio_profile = (struct radio_config) { .frequency_mhz = 433,
		.bandwidth_khz = 500, .spreading_factor = 7, .coding_rate = 5,
		.sync_word = 0x1424, .spi_hz = 2000000 };
	config.transmit_enabled = true;
	config.phy_ops = &fake_ops;
	config.clock_ops = &fake_clock_ops;
	config.io_context = &phy;
	config.clock_context = &clock;
	config.test_beacon_key = beacon_key;
	config.test_node_key = node_key;
	assert(radio_airtime_test_us(&config.radio_profile, NETWORK_FRAME_OVERHEAD + 8U) +
		radio_airtime_test_us(&config.radio_profile, NETWORK_FRAME_OVERHEAD + 9U) +
		2U * NETWORK_GUARD_MS * 1000U <= NETWORK_CONTENTION_MS * 1000U);
	assert(rt_network_runtime_start(&node, &config) == 0);
	assert(network_beacon_encode(&beacon, beacon_payload, sizeof(beacon_payload),
		&beacon_length) == 0);
	frame.type = NETWORK_FRAME_BEACON;
	frame.source = NETWORK_CONTROLLER_ID;
	frame.destination = NETWORK_BROADCAST_ID;
	frame.sequence = 1;
	frame.network_id = 77;
	frame.source_boot_nonce = controller_nonce;
	frame.controller_boot_nonce = controller_nonce;
	frame.payload_length = (uint16_t)beacon_length;
	memcpy(frame.payload, beacon_payload, beacon_length);
	assert(network_frame_encode(&frame, beacon_key, wire, sizeof(wire), &wire_length) == 0);
	memcpy(phy.rx, wire, wire_length);
	phy.rx_length = wire_length;
	clock.now_us = 200000;
	assert(rt_network_runtime_on_irq(node, SX126X_IRQ_RX_DONE, clock.now_us) == 0);
	airtime_us = radio_airtime_test_us(&config.radio_profile, NETWORK_FRAME_OVERHEAD + 8U);
	clock.now_us = clock.now_us + (uint64_t)NETWORK_FRAME_MS * 1000U -
		airtime_us - NETWORK_GUARD_MS * 1000U + 1U;
	assert(rt_network_runtime_tick(node) == 0);
	assert(phy.cad_count == 1);
	assert(rt_network_runtime_on_irq(node, SX126X_IRQ_CAD_DONE, clock.now_us) == 0);
	assert(phy.tx_length == 0); /* JOIN ToA plus guard does not fit before next beacon. */
	rt_network_runtime_stop(node);
	config.radio_profile.spreading_factor = 8;
	config.radio_profile.bandwidth_khz = 125;
	assert(radio_airtime_test_us(&config.radio_profile, NETWORK_FRAME_OVERHEAD + 8U) +
		radio_airtime_test_us(&config.radio_profile, NETWORK_FRAME_OVERHEAD + 9U) +
		2U * NETWORK_GUARD_MS * 1000U > NETWORK_CONTENTION_MS * 1000U);
	assert(rt_network_runtime_start(&node, &config) == -ERANGE);
	config.radio_profile.spreading_factor = 12;
	config.radio_profile.bandwidth_khz = 125;
	assert(rt_network_runtime_start(&node, &config) == -ERANGE);
	uloop_done();
}

static void real_timer_watchdog_cb(struct uloop_timeout *timer)
{
	(void)timer;
	uloop_end();
}

static void test_real_uloop_timer_dispatch(void)
{
	static const uint8_t beacon_key[32] = { 0x41 };
	struct rt_network_test_peer empty_registry[1] = { 0 };
	struct rt_network_runtime *controller = NULL;
	struct fake_phy phy = { 0 };
	struct rt_network_config config = { 0 };
	struct uloop_timeout watchdog = { .cb = real_timer_watchdog_cb };
	assert(uloop_init() == 0);
	config.role = RT_NETWORK_CONTROLLER;
	config.network_id = 77;
	config.queue_bytes = 65536;
	config.airtime_budget_us = 3000000;
	config.radio_profile = (struct radio_config) { .frequency_mhz = 433,
		.bandwidth_khz = 500, .spreading_factor = 7, .coding_rate = 5,
		.sync_word = 0x1424, .spi_hz = 2000000 };
	config.transmit_enabled = true;
	config.phy_ops = &fake_ops;
	config.io_context = &phy;
	config.test_beacon_key = beacon_key;
	config.test_registry = empty_registry;
	assert(rt_network_runtime_start(&controller, &config) == 0);
	assert(uloop_timeout_set(&watchdog, 100) == 0);
	uloop_run();
	assert(phy.tx_length > 0); /* start()'s zero-delay callback emitted the beacon. */
	rt_network_runtime_stop(controller);
	uloop_done();
}

static void test_missed_beacon_rejoins(void)
{
	static const uint8_t beacon_key[32] = { 0x41 };
	static const uint8_t node_key[32] = { 0x52 };
	struct rt_network_test_peer peers[2] = {
		{ .eui = { 0x02,0x12,0x34,0x56,0x78,0x9a,0xbc,0xde }, .psk = { 0x52 } },
		{ .eui = { 0x02,0x12,0x34,0x56,0x78,0x9a,0xbc,0xdf }, .psk = { 0x53 } },
	};
	struct fake_clock clock = { .now_us = 1 };
	struct fake_phy controller_phy = { 0 }, node_phy = { 0 };
	struct rt_network_runtime *controller = NULL, *node = NULL;
	struct rt_network_config controller_config = { 0 }, node_config = { 0 };
	struct radio_config profile = { .frequency_mhz = 433, .bandwidth_khz = 500,
		.spreading_factor = 7, .coding_rate = 5, .sync_word = 0x1424,
		.spi_hz = 2000000 };
	uint64_t grace_us, other_boot_nonce = 0x8877665544332211ULL;
	unsigned int cad_before_fresh_beacon;
	assert(uloop_init() == 0);
	controller_config.role = RT_NETWORK_CONTROLLER;
	controller_config.network_id = 77;
	controller_config.queue_bytes = 65536;
	controller_config.airtime_budget_us = 3000000;
	controller_config.radio_profile = profile;
	controller_config.transmit_enabled = true;
	controller_config.phy_ops = &fake_ops;
	controller_config.clock_ops = &fake_clock_ops;
	controller_config.io_context = &controller_phy;
	controller_config.clock_context = &clock;
	controller_config.test_beacon_key = beacon_key;
	controller_config.test_registry = peers;
	controller_config.test_registry_count = 2;
	node_config = controller_config;
	node_config.role = RT_NETWORK_NODE;
	node_config.node_eui = "02123456789abcde";
	node_config.test_node_key = node_key;
	node_config.test_registry = NULL;
	node_config.test_registry_count = 0;
	node_config.io_context = &node_phy;
	assert(rt_network_runtime_start(&controller, &controller_config) == 0);
	assert(rt_network_runtime_start(&node, &node_config) == 0);
	assert(rt_network_runtime_tick(controller) == 0);
	clock.now_us = 200000;
	inject_tx(controller, &controller_phy, node, &node_phy, &clock, SX126X_IRQ_RX_DONE);
	clock.now_us = 200000U +
		(uint64_t)(NETWORK_FRAME_MS - 100U) * 1000U;
	assert(rt_network_runtime_tick(node) == 0);
	assert(rt_network_runtime_on_irq(node, SX126X_IRQ_CAD_DONE, clock.now_us) == 0);
	clock.now_us += 10000;
	inject_tx(node, &node_phy, controller, &controller_phy, &clock, SX126X_IRQ_RX_DONE);
	clock.now_us += 10000;
	inject_tx(controller, &controller_phy, node, &node_phy, &clock, SX126X_IRQ_RX_DONE);
	clock.now_us = 200000U + (uint64_t)NETWORK_FRAME_MS * 1000U;
	assert(rt_network_runtime_tick(controller) == 0);
	assert(controller_phy.tx_length > 0);
	inject_tx(controller, &controller_phy, node, &node_phy, &clock, SX126X_IRQ_RX_DONE);
	assert_status(node, true, false, 0);

	/* The next controller beacon is lost; sync grace includes max beacon ToA + guard. */
	clock.now_us = 200000U + (uint64_t)NETWORK_FRAME_MS * 2U * 1000U;
	assert(rt_network_runtime_tick(controller) == 0);
	discard_tx(controller, &controller_phy, &clock);
	grace_us = (uint64_t)(NETWORK_FRAME_MS + NETWORK_GUARD_MS) * 1000U +
		((uint64_t)radio_airtime_test_us(&profile, NETWORK_FRAME_MAX_BYTES) + 999U) / 1000U * 1000U;
	clock.now_us = 200000U + (uint64_t)NETWORK_FRAME_MS * 1000U + grace_us + 1U;
	assert(rt_network_runtime_tick(node) == 0);
	assert_status(node, false, false, 0);
	cad_before_fresh_beacon = node_phy.cad_count;
	assert(node_phy.tx_length == 0); /* Sync timeout cannot guess a contention origin. */
	assert(rt_network_runtime_test_set_peer_demand(controller,
		NETWORK_FIRST_NODE_ID + 1U, other_boot_nonce,
		radio_airtime_test_us(&profile, NETWORK_DATA_FRAME_MAX_BYTES)) == 0);
	clock.now_us = 200000U + (uint64_t)NETWORK_FRAME_MS * 3U * 1000U;
	assert(rt_network_runtime_tick(controller) == 0);
	{
		struct network_frame frame;
		struct network_beacon beacon;
		uint8_t grant;
		bool other_node_grant = false;
		assert(network_frame_peek(controller_phy.tx, controller_phy.tx_length, &frame) == 0);
		assert(network_beacon_decode(frame.payload, frame.payload_length, &beacon) == 0);
		for (grant = 0; grant < beacon.grant_count; grant++)
			other_node_grant |= beacon.grants[grant].node_id == NETWORK_FIRST_NODE_ID + 1U;
		assert(other_node_grant);
	}
	inject_tx(controller, &controller_phy, node, &node_phy, &clock, SX126X_IRQ_RX_DONE);
	assert(node_phy.tx_length == 0);
	clock.now_us += 500000U;
	assert(rt_network_runtime_tick(node) == 0);
	assert(node_phy.cad_count == cad_before_fresh_beacon);
	assert(node_phy.tx_length == 0); /* Never contend through node 2's grant. */
	clock.now_us = 200000U + (uint64_t)NETWORK_FRAME_MS * 3U * 1000U +
		(uint64_t)(NETWORK_FRAME_MS - 100U) * 1000U;
	assert(rt_network_runtime_tick(node) == 0);
	assert(node_phy.cad_count > cad_before_fresh_beacon);
	assert(rt_network_runtime_on_irq(node, SX126X_IRQ_CAD_DONE, clock.now_us) == 0);
	assert(node_phy.tx_length > 0);
	clock.now_us += 10000;
	inject_tx(node, &node_phy, controller, &controller_phy, &clock, SX126X_IRQ_RX_DONE);
	clock.now_us += 10000;
	inject_tx(controller, &controller_phy, node, &node_phy, &clock, SX126X_IRQ_RX_DONE);
	clock.now_us = 200000U + (uint64_t)NETWORK_FRAME_MS * 4U * 1000U;
	assert(rt_network_runtime_tick(controller) == 0);
	inject_tx(controller, &controller_phy, node, &node_phy, &clock, SX126X_IRQ_RX_DONE);
	assert_status(node, true, false, 0);
	rt_network_runtime_stop(node);
	rt_network_runtime_stop(controller);
	uloop_done();
}

static void inject_wire(struct rt_network_runtime *runtime, struct fake_phy *phy,
	struct fake_clock *clock, const uint8_t *wire, size_t length)
{
	assert(length <= sizeof(phy->rx));
	memcpy(phy->rx, wire, length);
	phy->rx_length = length;
	assert(rt_network_runtime_on_irq(runtime, SX126X_IRQ_RX_DONE, clock->now_us) == 0);
}

static void inject_uart_command_beacon(struct rt_network_runtime *runtime,
	struct fake_phy *phy, struct fake_clock *clock, const uint8_t beacon_key[32],
	const uint8_t node_key[32], uint64_t controller_nonce, uint32_t frame_number,
	uint32_t frame_sequence, uint16_t command_sequence, uint8_t marker)
{
	struct rt_command command = { .kind = RT_COMMAND_UART_WRITE,
		.chunk_count = 1, .data_length = 1, .data = { marker } };
	struct network_beacon beacon = { .frame_number = frame_number,
		.contention_ms = NETWORK_CONTENTION_MS,
		.downlink_ms = NETWORK_DEFAULT_DOWNLINK_MS,
		.has_command = true };
	struct network_frame frame = { .type = NETWORK_FRAME_BEACON,
		.source = NETWORK_CONTROLLER_ID, .destination = NETWORK_BROADCAST_ID,
		.sequence = frame_sequence, .network_id = 77,
		.source_boot_nonce = controller_nonce,
		.controller_boot_nonce = controller_nonce };
	uint8_t command_wire[NETWORK_BEACON_COMMAND_MAX_BYTES];
	uint8_t payload[NETWORK_FRAME_MAX_PAYLOAD], wire[NETWORK_FRAME_MAX_BYTES];
	size_t command_length, payload_length, wire_length;

	assert(rt_command_uuid_parse(marker == 'A' ?
		"123e4567-e89b-42d3-a456-426614174000" :
		"223e4567-e89b-42d3-a456-426614174000",
		command.request_uuid) == 0);
	assert(rt_command_encode(&command, command_wire, sizeof(command_wire),
		&command_length) == 0);
	beacon.command.target_node_id = NETWORK_FIRST_NODE_ID;
	beacon.command.sequence = command_sequence;
	beacon.command.length = (uint8_t)command_length;
	memcpy(beacon.command.bytes, command_wire, command_length);
	assert(network_beacon_command_sign(&beacon.command, 77, controller_nonce,
		frame_number, node_key, beacon.command.tag) == 0);
	assert(network_beacon_encode(&beacon, payload, sizeof(payload),
		&payload_length) == 0);
	frame.payload_length = (uint16_t)payload_length;
	memcpy(frame.payload, payload, payload_length);
	assert(network_frame_encode(&frame, beacon_key, wire, sizeof(wire),
		&wire_length) == 0);
	inject_wire(runtime, phy, clock, wire, wire_length);
}

static void test_reboot_join_clears_partial_reassembly(void)
{
	static const uint8_t beacon_key[32] = { 0x41 };
	static const uint8_t node_key[32] = { 0x52 };
	const uint8_t eui[8] = { 0x02,0x12,0x34,0x56,0x78,0x9a,0xbc,0xde };
	struct rt_network_test_peer peer = {
		.eui = { 0x02,0x12,0x34,0x56,0x78,0x9a,0xbc,0xde }, .psk = { 0x52 },
	};
	struct fake_clock clock = { .now_us = 1 };
	struct fake_phy phy = { 0 };
	struct rt_network_runtime *controller = NULL;
	struct rt_network_config config = { 0 };
	struct network_frame frame = { 0 };
	struct network_fragment fragments[NETWORK_MAX_FRAGMENTS];
	uint8_t raw[200], join_payload[8], payload[NETWORK_FRAME_MAX_PAYLOAD];
	uint8_t wire[NETWORK_FRAME_MAX_BYTES];
	const uint8_t reboot_raw[3] = { 'N', 'E', 'W' };
	size_t fragment_count, payload_length, wire_length;
	uint64_t controller_boot;
	uint64_t old_boot = 0x1111222233334444ULL, new_boot = 0x5555666677778888ULL;
	assert(uloop_init() == 0);
	config.role = RT_NETWORK_CONTROLLER;
	config.network_id = 77;
	config.queue_bytes = 65536;
	config.airtime_budget_us = 3000000;
	config.radio_profile = (struct radio_config) { .frequency_mhz = 433,
		.bandwidth_khz = 500, .spreading_factor = 7, .coding_rate = 5,
		.sync_word = 0x1424, .spi_hz = 2000000 };
	config.transmit_enabled = true;
	config.phy_ops = &fake_ops;
	config.clock_ops = &fake_clock_ops;
	config.io_context = &phy;
	config.clock_context = &clock;
	config.test_beacon_key = beacon_key;
	config.test_registry = &peer;
	config.test_registry_count = 1;
	assert(rt_network_runtime_start(&controller, &config) == 0);
	assert(rt_network_runtime_tick(controller) == 0);
	discard_tx(controller, &phy, &clock); /* Complete the initial beacon. */
	controller_boot = status_u64(controller, "network_boot_nonce");
	assert(network_join_payload_encode(eui, join_payload) == 0);
	frame.type = NETWORK_FRAME_JOIN;
	frame.source = NETWORK_UNASSIGNED_NODE_ID;
	frame.destination = NETWORK_CONTROLLER_ID;
	frame.sequence = 1;
	frame.network_id = 77;
	frame.source_boot_nonce = old_boot;
	frame.payload_length = sizeof(join_payload);
	memcpy(frame.payload, join_payload, sizeof(join_payload));
	assert(network_frame_encode(&frame, node_key, wire, sizeof(wire), &wire_length) == 0);
	clock.now_us += 1000;
	inject_wire(controller, &phy, &clock, wire, wire_length);
	discard_tx(controller, &phy, &clock); /* Complete JOIN_RESPONSE. */

	for (size_t i = 0; i < sizeof(raw); i++) raw[i] = (uint8_t)(i * 73U + 19U);
	assert(network_block_fragment(100, 0, 0, sizeof(raw), NETWORK_CODEC_RAW,
		raw, sizeof(raw), fragments, NETWORK_MAX_FRAGMENTS, &fragment_count) == 0);
	assert(fragment_count > 1);
	assert(network_fragment_pack(&fragments[0], payload, sizeof(payload), &payload_length) == 0);
	memset(&frame, 0, sizeof(frame));
	frame.type = NETWORK_FRAME_DATA;
	frame.source = NETWORK_FIRST_NODE_ID;
	frame.destination = NETWORK_CONTROLLER_ID;
	frame.sequence = 2;
	frame.network_id = 77;
	frame.source_boot_nonce = old_boot;
	frame.controller_boot_nonce = controller_boot;
	frame.payload_length = (uint16_t)payload_length;
	memcpy(frame.payload, payload, payload_length);
	assert(network_frame_encode(&frame, node_key, wire, sizeof(wire), &wire_length) == 0);
	inject_wire(controller, &phy, &clock, wire, wire_length); /* Leaves old partial slot active. */

	/* Reboot JOIN carries the EUI, not a preassigned radio ID. */
	memset(&frame, 0, sizeof(frame));
	frame.type = NETWORK_FRAME_JOIN;
	frame.source = NETWORK_UNASSIGNED_NODE_ID;
	frame.destination = NETWORK_CONTROLLER_ID;
	frame.sequence = 1;
	frame.network_id = 77;
	frame.source_boot_nonce = new_boot;
	frame.payload_length = sizeof(eui);
	memcpy(frame.payload, eui, sizeof(eui));
	assert(network_frame_encode(&frame, node_key, wire, sizeof(wire), &wire_length) == 0);
	clock.now_us += 1000;
	inject_wire(controller, &phy, &clock, wire, wire_length);
	assert(phy.tx_length > 0); /* A new nonce is assigned the same EUI registry slot. */
	discard_tx(controller, &phy, &clock);

	assert(network_block_fragment(101, 7, 0, sizeof(reboot_raw), NETWORK_CODEC_RAW,
		reboot_raw, sizeof(reboot_raw), fragments, NETWORK_MAX_FRAGMENTS,
		&fragment_count) == 0);
	assert(fragment_count == 1);
	assert(network_fragment_pack(&fragments[0], payload, sizeof(payload), &payload_length) == 0);
	memset(&frame, 0, sizeof(frame));
	frame.type = NETWORK_FRAME_DATA;
	frame.source = NETWORK_FIRST_NODE_ID;
	frame.destination = NETWORK_CONTROLLER_ID;
	frame.sequence = 2;
	frame.network_id = 77;
	frame.source_boot_nonce = new_boot;
	frame.controller_boot_nonce = controller_boot;
	frame.payload_length = (uint16_t)payload_length;
	memcpy(frame.payload, payload, payload_length);
	assert(network_frame_encode(&frame, node_key, wire, sizeof(wire), &wire_length) == 0);
	inject_wire(controller, &phy, &clock, wire, wire_length);
	{
		uint32_t next_offset;
		assert(rt_network_runtime_test_delivery_offset(controller,
			NETWORK_FIRST_NODE_ID, 101, &next_offset) == 0);
		assert(next_offset == sizeof(reboot_raw)); /* Different stream/block cleared stale slot. */
	}
	rt_network_runtime_stop(controller);
	uloop_done();
}

static void test_retry_gap_freezes_and_promotes_next_range(void)
{
	static const uint8_t beacon_key[32] = { 0x41 };
	struct fake_clock clock = { .now_us = 1 };
	struct fake_phy phy = { 0 };
	struct rt_network_runtime *node = NULL;
	struct rt_network_config config = { 0 };
	struct blob_buf status = {};
	struct blob_attr *fields[__STATUS_MAX] = {};
	assert(uloop_init() == 0);
	config.role = RT_NETWORK_NODE;
	config.network_id = 77;
	config.node_eui = "02123456789abcde";
	config.queue_bytes = 65536;
	config.radio_profile = (struct radio_config) { .frequency_mhz = 433,
		.bandwidth_khz = 500, .spreading_factor = 7, .coding_rate = 5,
		.sync_word = 0x1424, .spi_hz = 2000000 };
	config.transmit_enabled = true;
	config.phy_ops = &fake_ops;
	config.clock_ops = &fake_clock_ops;
	config.io_context = &phy;
	config.clock_context = &clock;
	config.test_beacon_key = beacon_key;
	config.test_node_key = beacon_key;
	assert(rt_network_runtime_start(&node, &config) == 0);
	assert(rt_network_runtime_capture(node, (const uint8_t *)"ABCD", 4) == 0);
	clock.now_us = 4000001;
	assert(rt_network_runtime_tick(node) == 0);
	assert_status(node, false, true, 0);
	assert(rt_network_runtime_capture(node, (const uint8_t *)"EFGH", 4) == 0);
	clock.now_us = 8000001;
	assert(rt_network_runtime_tick(node) == 0);
	assert(rt_network_runtime_test_exhaust_fragment(node, 0, false) == 0);
	blob_buf_init(&status, 0);
	rt_network_runtime_add_status(node, &status);
	blobmsg_parse(status_policy, __STATUS_MAX, fields,
		blobmsg_data(status.head), blobmsg_len(status.head));
	assert(fields[STATUS_GAP_PENDING] && blobmsg_get_u8(fields[STATUS_GAP_PENDING]));
	assert(fields[STATUS_GAP_BEFORE_QUEUE] && blobmsg_get_u8(fields[STATUS_GAP_BEFORE_QUEUE]));
	assert(fields[STATUS_GAP_REASON] && blobmsg_get_u32(fields[STATUS_GAP_REASON]) == 2U);
	assert(fields[STATUS_GAP_FROM] && blobmsg_get_u32(fields[STATUS_GAP_FROM]) == 0U);
	assert(fields[STATUS_GAP_TO] && blobmsg_get_u32(fields[STATUS_GAP_TO]) == 8U);
	assert(fields[STATUS_BLOCK_ACTIVE] && !blobmsg_get_u8(fields[STATUS_BLOCK_ACTIVE]));
	assert(fields[STATUS_QUEUE_BYTES] && blobmsg_get_u32(fields[STATUS_QUEUE_BYTES]) == 0U);
	assert(fields[STATUS_SERIAL_BUFFERED] && blobmsg_get_u32(fields[STATUS_SERIAL_BUFFERED]) == 0U);
	blob_buf_free(&status);

	/* Once [0,8) is sent, an intervening UART drop becomes a distinct [8,9). */
	assert(rt_network_runtime_test_mark_gap_sent(node) == 0);
	assert(rt_network_runtime_capture(node, (const uint8_t *)"I", 1) == 0);
	blob_buf_init(&status, 0);
	rt_network_runtime_add_status(node, &status);
	memset(fields, 0, sizeof(fields));
	blobmsg_parse(status_policy, __STATUS_MAX, fields,
		blobmsg_data(status.head), blobmsg_len(status.head));
	assert(fields[STATUS_GAP_FROM] && blobmsg_get_u32(fields[STATUS_GAP_FROM]) == 0U);
	assert(fields[STATUS_GAP_TO] && blobmsg_get_u32(fields[STATUS_GAP_TO]) == 8U);
	assert(fields[STATUS_NEXT_GAP_PENDING] && blobmsg_get_u8(fields[STATUS_NEXT_GAP_PENDING]));
	assert(fields[STATUS_NEXT_GAP_FROM] && blobmsg_get_u32(fields[STATUS_NEXT_GAP_FROM]) == 8U);
	assert(fields[STATUS_NEXT_GAP_TO] && blobmsg_get_u32(fields[STATUS_NEXT_GAP_TO]) == 9U);
	blob_buf_free(&status);

	assert(rt_network_runtime_test_ack_gap(node) == 0);
	blob_buf_init(&status, 0);
	rt_network_runtime_add_status(node, &status);
	memset(fields, 0, sizeof(fields));
	blobmsg_parse(status_policy, __STATUS_MAX, fields,
		blobmsg_data(status.head), blobmsg_len(status.head));
	assert(fields[STATUS_GAP_PENDING] && blobmsg_get_u8(fields[STATUS_GAP_PENDING]));
	assert(fields[STATUS_GAP_FROM] && blobmsg_get_u32(fields[STATUS_GAP_FROM]) == 8U);
	assert(fields[STATUS_GAP_TO] && blobmsg_get_u32(fields[STATUS_GAP_TO]) == 9U);
	assert(fields[STATUS_RAW_OFFSET] && blobmsg_get_u32(fields[STATUS_RAW_OFFSET]) == 8U);
	assert(fields[STATUS_GAP_IN_FLIGHT] && !blobmsg_get_u8(fields[STATUS_GAP_IN_FLIGHT]));
	blob_buf_free(&status);
	assert(rt_network_runtime_test_mark_gap_sent(node) == 0);
	assert(rt_network_runtime_test_ack_gap(node) == 0);
	assert(status_u32(node, "network_raw_offset") == 9U);
	assert(rt_network_runtime_capture(node, (const uint8_t *)"J", 1) == 0);
	clock.now_us = 12000001;
	assert(rt_network_runtime_tick(node) == 0);
	assert_status(node, false, true, 0);
	assert(status_u32(node, "network_raw_offset") == 9U);
	rt_network_runtime_stop(node);
	uloop_done();
}

static void test_controller_accepts_two_gaps_then_data(void)
{
	static const uint8_t beacon_key[32] = { 0x41 };
	static const uint8_t node_key[32] = { 0x52 };
	const uint8_t eui[8] = { 0x02,0x12,0x34,0x56,0x78,0x9a,0xbc,0xde };
	struct rt_network_test_peer peer = {
		.eui = { 0x02,0x12,0x34,0x56,0x78,0x9a,0xbc,0xde }, .psk = { 0x52 },
	};
	struct fake_clock clock = { .now_us = 1 };
	struct fake_phy phy = { 0 };
	struct rt_network_runtime *controller = NULL;
	struct rt_network_config config = { 0 };
	struct network_frame frame = { 0 };
	struct network_fragment fragments[NETWORK_MAX_FRAGMENTS];
	const uint8_t delivered_prefix[4] = { 'A', 'B', 'C', 'D' };
	uint8_t raw[200], payload[NETWORK_FRAME_MAX_PAYLOAD], wire[NETWORK_FRAME_MAX_BYTES];
	size_t fragment_count, payload_length, wire_length;
	uint64_t controller_boot, node_boot = 0x123456789abcdef0ULL;
	uint32_t next_offset;
	assert(uloop_init() == 0);
	config.role = RT_NETWORK_CONTROLLER;
	config.network_id = 77;
	config.queue_bytes = 65536;
	config.airtime_budget_us = 3000000;
	config.radio_profile = (struct radio_config) { .frequency_mhz = 433,
		.bandwidth_khz = 500, .spreading_factor = 7, .coding_rate = 5,
		.sync_word = 0x1424, .spi_hz = 2000000 };
	config.transmit_enabled = true;
	config.phy_ops = &fake_ops;
	config.clock_ops = &fake_clock_ops;
	config.io_context = &phy;
	config.clock_context = &clock;
	config.test_beacon_key = beacon_key;
	config.test_registry = &peer;
	config.test_registry_count = 1;
	config.host_port = 45671;
	config.host_psk_path = "fake-host-key";
	fake_host_publish_success = true;
	fake_host_last_event[0] = '\0';
	assert(rt_network_runtime_start(&controller, &config) == 0);
	assert(rt_network_runtime_tick(controller) == 0);
	discard_tx(controller, &phy, &clock);
	controller_boot = status_u64(controller, "network_boot_nonce");

	frame.type = NETWORK_FRAME_JOIN;
	frame.source = NETWORK_UNASSIGNED_NODE_ID;
	frame.destination = NETWORK_CONTROLLER_ID;
	frame.sequence = 1;
	frame.network_id = 77;
	frame.source_boot_nonce = node_boot;
	frame.payload_length = sizeof(eui);
	memcpy(frame.payload, eui, sizeof(eui));
	assert(network_frame_encode(&frame, node_key, wire, sizeof(wire), &wire_length) == 0);
	clock.now_us += 1000;
	inject_wire(controller, &phy, &clock, wire, wire_length);
	discard_tx(controller, &phy, &clock);

	/* The first block reached the controller, but its bitmap ACK is lost. */
	assert(network_block_fragment(900, 0, 0, sizeof(delivered_prefix), NETWORK_CODEC_RAW,
		delivered_prefix, sizeof(delivered_prefix), fragments, NETWORK_MAX_FRAGMENTS,
		&fragment_count) == 0);
	assert(fragment_count == 1);
	assert(network_fragment_pack(&fragments[0], payload, sizeof(payload), &payload_length) == 0);
	memset(&frame, 0, sizeof(frame));
	frame.type = NETWORK_FRAME_DATA;
	frame.source = NETWORK_FIRST_NODE_ID;
	frame.destination = NETWORK_CONTROLLER_ID;
	frame.sequence = 2;
	frame.network_id = 77;
	frame.source_boot_nonce = node_boot;
	frame.controller_boot_nonce = controller_boot;
	frame.payload_length = (uint16_t)payload_length;
	memcpy(frame.payload, payload, payload_length);
	assert(network_frame_encode(&frame, node_key, wire, sizeof(wire), &wire_length) == 0);
	inject_wire(controller, &phy, &clock, wire, wire_length);
	assert(rt_network_runtime_test_delivery_offset(controller, NETWORK_FIRST_NODE_ID,
		900, &next_offset) == 0);
	assert(next_offset == 4U);

	/* Another abandoned stream/block remains partial in this source's slot. */
	memset(raw, 0x5a, sizeof(raw));
	assert(network_block_fragment(901, 99, 0, sizeof(raw), NETWORK_CODEC_RAW,
		raw, sizeof(raw), fragments, NETWORK_MAX_FRAGMENTS, &fragment_count) == 0);
	assert(fragment_count > 1);
	assert(network_fragment_pack(&fragments[0], payload, sizeof(payload), &payload_length) == 0);
	memset(&frame, 0, sizeof(frame));
	frame.type = NETWORK_FRAME_DATA;
	frame.source = NETWORK_FIRST_NODE_ID;
	frame.destination = NETWORK_CONTROLLER_ID;
	frame.sequence = 3;
	frame.network_id = 77;
	frame.source_boot_nonce = node_boot;
	frame.controller_boot_nonce = controller_boot;
	frame.payload_length = (uint16_t)payload_length;
	memcpy(frame.payload, payload, payload_length);
	assert(network_frame_encode(&frame, node_key, wire, sizeof(wire), &wire_length) == 0);
	inject_wire(controller, &phy, &clock, wire, wire_length); /* Leaves a stale partial slot. */

	/* [0,8) overlaps delivered [0,4); only the suffix [4,8) is published. */
	for (unsigned i = 0; i < 2; i++) {
		uint32_t from = i ? 8U : 0U;
		uint32_t to = i ? 9U : 8U;
		memset(&frame, 0, sizeof(frame));
		frame.type = NETWORK_FRAME_STATUS;
		frame.source = NETWORK_FIRST_NODE_ID;
		frame.destination = NETWORK_CONTROLLER_ID;
		frame.sequence = 4U + i;
		frame.network_id = 77;
		frame.source_boot_nonce = node_boot;
		frame.controller_boot_nonce = controller_boot;
		frame.payload[0] = 1U;
		frame.payload[1] = (uint8_t)900;
		frame.payload[2] = (uint8_t)(900U >> 8);
		frame.payload[3] = (uint8_t)(900U >> 16);
		frame.payload[4] = (uint8_t)(900U >> 24);
		frame.payload[5] = (uint8_t)from;
		frame.payload[9] = (uint8_t)to;
		frame.payload_length = 14;
		assert(network_frame_encode(&frame, node_key, wire, sizeof(wire), &wire_length) == 0);
		clock.now_us += 1000;
		inject_wire(controller, &phy, &clock, wire, wire_length);
		assert(rt_network_runtime_test_delivery_offset(controller, NETWORK_FIRST_NODE_ID,
			900, &next_offset) == 0);
		assert(next_offset == to);
		assert(strstr(fake_host_last_event, "\"type\":\"stream.gap\""));
		if (i == 0) {
			assert(strstr(fake_host_last_event, "\"fromOffset\":4"));
			assert(strstr(fake_host_last_event, "\"toOffset\":8"));
		} else {
			assert(strstr(fake_host_last_event, "\"fromOffset\":8"));
			assert(strstr(fake_host_last_event, "\"toOffset\":9"));
		}
	}

	/* A genuine forward hole remains rejected and does not move the cursor. */
	memset(&frame, 0, sizeof(frame));
	frame.type = NETWORK_FRAME_STATUS;
	frame.source = NETWORK_FIRST_NODE_ID;
	frame.destination = NETWORK_CONTROLLER_ID;
	frame.sequence = 6;
	frame.network_id = 77;
	frame.source_boot_nonce = node_boot;
	frame.controller_boot_nonce = controller_boot;
	frame.payload[0] = 1U;
	frame.payload[1] = (uint8_t)900;
	frame.payload[2] = (uint8_t)(900U >> 8);
	frame.payload[3] = (uint8_t)(900U >> 16);
	frame.payload[4] = (uint8_t)(900U >> 24);
	frame.payload[5] = 11U;
	frame.payload[9] = 12U;
	frame.payload_length = 14;
	assert(network_frame_encode(&frame, node_key, wire, sizeof(wire), &wire_length) == 0);
	clock.now_us += 1000;
	inject_wire(controller, &phy, &clock, wire, wire_length);
	assert(rt_network_runtime_test_delivery_offset(controller, NETWORK_FIRST_NODE_ID,
		900, &next_offset) == 0);
	assert(next_offset == 9U);

	/* New metadata at offset 9 proves GAP acceptance cleared source index 1. */
	{
		const uint8_t final_byte = 'J';
		assert(network_block_fragment(900, 2, 9, 1, NETWORK_CODEC_RAW,
			&final_byte, 1, fragments, NETWORK_MAX_FRAGMENTS, &fragment_count) == 0);
		assert(fragment_count == 1);
		assert(network_fragment_pack(&fragments[0], payload, sizeof(payload), &payload_length) == 0);
		memset(&frame, 0, sizeof(frame));
		frame.type = NETWORK_FRAME_DATA;
		frame.source = NETWORK_FIRST_NODE_ID;
		frame.destination = NETWORK_CONTROLLER_ID;
		frame.sequence = 7;
		frame.network_id = 77;
		frame.source_boot_nonce = node_boot;
		frame.controller_boot_nonce = controller_boot;
		frame.payload_length = (uint16_t)payload_length;
		memcpy(frame.payload, payload, payload_length);
		assert(network_frame_encode(&frame, node_key, wire, sizeof(wire), &wire_length) == 0);
		clock.now_us += 1000;
		inject_wire(controller, &phy, &clock, wire, wire_length);
		assert(rt_network_runtime_test_delivery_offset(controller, NETWORK_FIRST_NODE_ID,
			900, &next_offset) == 0);
		assert(next_offset == 10U);
	}
	rt_network_runtime_stop(controller);
	fake_host_publish_success = false;
	uloop_done();
}

static void test_old_authenticated_beacon_nonce_is_rejected(void)
{
	static const uint8_t key[32] = { 0x61 };
	struct fake_clock clock = { .now_us = 1 };
	struct fake_phy phy = { 0 };
	struct rt_network_runtime *node = NULL;
	struct rt_network_config config = { 0 };
	struct network_beacon beacon = { .contention_ms = NETWORK_CONTENTION_MS,
		.downlink_ms = NETWORK_DEFAULT_DOWNLINK_MS };
	struct network_frame frame = { 0 };
	char serial_path[128];
	uint8_t body[NETWORK_FRAME_MAX_PAYLOAD], wire[NETWORK_FRAME_MAX_BYTES], join_response[9];
	size_t body_length, wire_length;
	uint64_t node_boot, old_controller = 0x1111222233334444ULL;
	uint64_t new_controller = 0x5555666677778888ULL;
	uint8_t serial_byte;
	int serial_master, serial_slave, flags;
	assert(uloop_init() == 0);
	config.role = RT_NETWORK_NODE;
	config.network_id = 77;
	config.node_eui = "02123456789abcde";
	config.queue_bytes = 65536;
	config.radio_profile = (struct radio_config) { .frequency_mhz = 433,
		.bandwidth_khz = 500, .spreading_factor = 7, .coding_rate = 5,
		.sync_word = 0x1424, .spi_hz = 2000000 };
	config.transmit_enabled = true;
	config.phy_ops = &fake_ops;
	config.clock_ops = &fake_clock_ops;
	config.io_context = &phy;
	config.clock_context = &clock;
	config.test_beacon_key = key;
	config.test_node_key = key;
	assert(openpty(&serial_master, &serial_slave, serial_path, NULL, NULL) == 0);
	flags = fcntl(serial_master, F_GETFL, 0);
	assert(flags >= 0 && fcntl(serial_master, F_SETFL, flags | O_NONBLOCK) == 0);
	config.serial_path = serial_path;
	assert(rt_network_runtime_start(&node, &config) == 0);
	close(serial_slave);
	node_boot = status_u64(node, "network_boot_nonce");
	assert(network_beacon_encode(&beacon, body, sizeof(body), &body_length) == 0);
	frame.type = NETWORK_FRAME_BEACON;
	frame.source = NETWORK_CONTROLLER_ID;
	frame.destination = NETWORK_BROADCAST_ID;
	frame.sequence = 1;
	frame.network_id = 77;
	frame.source_boot_nonce = old_controller;
	frame.controller_boot_nonce = old_controller;
	frame.payload_length = (uint16_t)body_length;
	memcpy(frame.payload, body, body_length);
	assert(network_frame_encode(&frame, key, wire, sizeof(wire), &wire_length) == 0);
	inject_wire(node, &phy, &clock, wire, wire_length);
	assert(status_u64(node, "network_beacon_replay_controller_nonce") == old_controller);

	assert(network_join_response_payload_encode(NETWORK_FIRST_NODE_ID, node_boot,
		join_response) == 0);
	memset(&frame, 0, sizeof(frame));
	frame.type = NETWORK_FRAME_JOIN_RESPONSE;
	frame.source = NETWORK_CONTROLLER_ID;
	frame.destination = NETWORK_UNASSIGNED_NODE_ID;
	frame.sequence = 1;
	frame.network_id = 77;
	frame.source_boot_nonce = old_controller;
	frame.controller_boot_nonce = old_controller;
	frame.payload_length = sizeof(join_response);
	memcpy(frame.payload, join_response, sizeof(join_response));
	assert(network_frame_encode(&frame, key, wire, sizeof(wire), &wire_length) == 0);
	inject_wire(node, &phy, &clock, wire, wire_length);
	assert_status(node, true, false, 0);

	/* A high sequence in epoch A executes and is remembered per node. */
	inject_uart_command_beacon(node, &phy, &clock, key, key, old_controller,
		2, 2, 1000, 'A');
	assert(read(serial_master, &serial_byte, sizeof(serial_byte)) == 1);
	assert(serial_byte == 'A');

	beacon.frame_number = 2;
	beacon.has_command = false;
	assert(network_beacon_encode(&beacon, body, sizeof(body), &body_length) == 0);
	memset(&frame, 0, sizeof(frame));
	frame.type = NETWORK_FRAME_BEACON;
	frame.source = NETWORK_CONTROLLER_ID;
	frame.destination = NETWORK_BROADCAST_ID;
	frame.sequence = 1;
	frame.network_id = 77;
	frame.source_boot_nonce = new_controller;
	frame.controller_boot_nonce = new_controller;
	frame.payload_length = (uint16_t)body_length;
	memcpy(frame.payload, body, body_length);
	assert(network_frame_encode(&frame, key, wire, sizeof(wire), &wire_length) == 0);
	inject_wire(node, &phy, &clock, wire, wire_length);
	assert_status(node, false, false, 0);
	assert(status_u64(node, "network_beacon_replay_controller_nonce") == new_controller);

	/* Captured A is validly authenticated but must not reset session B. */
	frame.source_boot_nonce = old_controller;
	frame.controller_boot_nonce = old_controller;
	frame.sequence = 2;
	assert(network_frame_encode(&frame, key, wire, sizeof(wire), &wire_length) == 0);
	inject_wire(node, &phy, &clock, wire, wire_length);
	assert(status_u64(node, "network_beacon_replay_controller_nonce") == new_controller);
	assert(status_u32(node, "network_frame") == 2U);
	assert_status(node, false, false, 0);

	assert(network_join_response_payload_encode(NETWORK_FIRST_NODE_ID, node_boot,
		join_response) == 0);
	memset(&frame, 0, sizeof(frame));
	frame.type = NETWORK_FRAME_JOIN_RESPONSE;
	frame.source = NETWORK_CONTROLLER_ID;
	frame.destination = NETWORK_UNASSIGNED_NODE_ID;
	frame.sequence = 1;
	frame.network_id = 77;
	frame.source_boot_nonce = new_controller;
	frame.controller_boot_nonce = new_controller;
	frame.payload_length = sizeof(join_response);
	memcpy(frame.payload, join_response, sizeof(join_response));
	assert(network_frame_encode(&frame, key, wire, sizeof(wire), &wire_length) == 0);
	inject_wire(node, &phy, &clock, wire, wire_length);
	assert_status(node, true, false, 0);

	/* The restarted controller begins at sequence 1; it must execute after rejoin. */
	inject_uart_command_beacon(node, &phy, &clock, key, key, new_controller,
		3, 2, 1, 'B');
	assert(read(serial_master, &serial_byte, sizeof(serial_byte)) == 1);
	assert(serial_byte == 'B');
	assert(status_u64(node, "network_controller_boot_nonce") == new_controller);
	rt_network_runtime_stop(node);
	close(serial_master);
	uloop_done();
}

static void test_demand_lease_expires_across_frame_rollover(void)
{
	static const uint8_t beacon_key[32] = { 0x41 };
	struct rt_network_test_peer peer = {
		.eui = { 0x02,0x12,0x34,0x56,0x78,0x9a,0xbc,0xde },
		.psk = { 0x52 },
	};
	struct fake_clock clock = { .now_us = 1 };
	struct fake_phy phy = { 0 };
	struct rt_network_runtime *controller = NULL;
	struct rt_network_config config = { 0 };
	uint64_t peer_boot = 0x1234432112344321ULL;
	uint32_t packet_airtime;
	unsigned int frame_index;
	assert(uloop_init() == 0);
	config.role = RT_NETWORK_CONTROLLER;
	config.network_id = 77;
	config.queue_bytes = 65536;
	config.airtime_budget_us = 3450000;
	config.radio_profile = (struct radio_config) { .frequency_mhz = 433,
		.bandwidth_khz = 500, .spreading_factor = 7, .coding_rate = 5,
		.sync_word = 0x1424, .spi_hz = 2000000 };
	config.transmit_enabled = true;
	config.phy_ops = &fake_ops;
	config.clock_ops = &fake_clock_ops;
	config.io_context = &phy;
	config.clock_context = &clock;
	config.test_beacon_key = beacon_key;
	config.test_registry = &peer;
	config.test_registry_count = 1;
	assert(rt_network_runtime_start(&controller, &config) == 0);
	assert(rt_network_runtime_test_set_frame_number(controller, UINT32_MAX - 2U) == 0);
	packet_airtime = radio_airtime_test_us(&config.radio_profile,
		NETWORK_DATA_FRAME_MAX_BYTES);
	assert(rt_network_runtime_test_set_peer_demand(controller, NETWORK_FIRST_NODE_ID,
		peer_boot, packet_airtime) == 0);
	for (frame_index = 0; frame_index < 3U; frame_index++) {
		struct network_frame frame;
		struct network_beacon beacon;
		bool has_node_grant = false;
		uint8_t i;
		if (frame_index)
			clock.now_us += (uint64_t)NETWORK_FRAME_MS * 1000U;
		assert(rt_network_runtime_tick(controller) == 0);
		assert(phy.tx_length > 0);
		assert(network_frame_peek(phy.tx, phy.tx_length, &frame) == 0);
		assert(network_beacon_decode(frame.payload, frame.payload_length, &beacon) == 0);
		assert(beacon.frame_number == (uint32_t)(UINT32_MAX - 1U + frame_index));
		for (i = 0; i < beacon.grant_count; i++)
			has_node_grant |= beacon.grants[i].node_id == NETWORK_FIRST_NODE_ID;
		assert(has_node_grant == (frame_index < 2U));
		discard_tx(controller, &phy, &clock);
	}
	rt_network_runtime_stop(controller);
	uloop_done();
}

int main(void)
{
	static const uint8_t beacon_key[32] = {
		0x31,0x28,0x67,0x9a,0x04,0x55,0x13,0xa2,0x80,0x9d,0xfe,0x10,0x64,0x81,0x32,0xb7,
		0x99,0x20,0x42,0x63,0x52,0xa8,0x11,0x90,0xee,0x72,0x04,0x18,0x2a,0xc1,0x54,0x01
	};
	static const uint8_t node_key[32] = {
		0x87,0x66,0x55,0x44,0x33,0x22,0x11,0x00,0x3a,0x4b,0x5c,0x6d,0x7e,0x8f,0x90,0xa1,
		0x12,0x23,0x34,0x45,0x56,0x67,0x78,0x89,0x9a,0xab,0xbc,0xcd,0xde,0xef,0xf0,0x01
	};
	const uint8_t eui[8] = { 0x02,0x12,0x34,0x56,0x78,0x9a,0xbc,0xde };
	const char eui_text[] = "02123456789abcde";
	struct rt_network_test_peer peer = { .eui = {0x02,0x12,0x34,0x56,0x78,0x9a,0xbc,0xde} };
	struct rt_network_config controller_config = { 0 }, node_config = { 0 };
	struct rt_network_runtime *controller = NULL, *node = NULL;
	struct fake_clock clock = { 1 };
	struct fake_phy controller_phy = { 0 }, node_phy = { 0 };
	struct blob_buf write_payload = {}, host_result = {};
	struct fake_host_registration *controller_host;
	static const char request_id[] = "123e4567-e89b-42d3-a456-426614174000";
	struct radio_config profile = {
		.frequency_mhz = 433, .bandwidth_khz = 500, .spreading_factor = 7,
		.coding_rate = 5, .sync_word = 0x1424, .spi_hz = 2000000,
	};
	assert(uloop_init() == 0);
	memcpy(peer.psk, node_key, sizeof(node_key));
	controller_config.role = RT_NETWORK_CONTROLLER;
	controller_config.network_id = 77;
	controller_config.queue_bytes = 65536;
	controller_config.airtime_budget_us = 3000000;
	controller_config.radio_profile = profile;
	controller_config.transmit_enabled = true;
	controller_config.phy_ops = &fake_ops;
	controller_config.clock_ops = &fake_clock_ops;
	controller_config.io_context = &controller_phy;
	controller_config.clock_context = &clock;
	controller_config.test_beacon_key = beacon_key;
	controller_config.test_registry = &peer;
	controller_config.test_registry_count = 1;
	controller_config.host_port = 45671;
	controller_config.host_psk_path = "fake-host-key";
	node_config = controller_config;
	node_config.role = RT_NETWORK_NODE;
	node_config.node_eui = eui_text;
	node_config.controller_ipv4 = NULL;
	node_config.test_node_key = node_key;
	node_config.test_registry = NULL;
	node_config.test_registry_count = 0;
	node_config.io_context = &node_phy;
	node_config.clock_context = &clock;
	assert(memcmp(peer.eui, eui, sizeof(eui)) == 0);
	assert(rt_network_runtime_start(&controller, &controller_config) == 0);
	assert(rt_network_runtime_start(&node, &node_config) == 0);
	assert(host_for_context(controller) && host_for_context(controller)->callback);
	controller_host = host_for_context(controller);
	assert(rt_network_runtime_capture(node, (const uint8_t *)"hello", 5) == 0);
	assert(rt_network_runtime_tick(controller) == 0);
	assert(controller_phy.tx_length > 0); /* Initial authenticated beacon. */
	clock.now_us = 200000;
	inject_tx(controller, &controller_phy, node, &node_phy, &clock, SX126X_IRQ_RX_DONE);

	clock.now_us = 200000U +
		(uint64_t)(NETWORK_FRAME_MS - 100U) * 1000U;
	assert(rt_network_runtime_tick(node) == 0);
	assert(node_phy.cad_count > 0); /* JOIN is attempted only in the contention tail. */
	assert(rt_network_runtime_on_irq(node, SX126X_IRQ_CAD_DONE, clock.now_us) == 0);
	assert(node_phy.tx_length > 0);
	clock.now_us += 10000;
	inject_tx(node, &node_phy, controller, &controller_phy, &clock, SX126X_IRQ_RX_DONE);
	assert(controller_phy.tx_length > 0); /* Controller-assigned JOIN_RESPONSE. */
	clock.now_us += 10000;
	inject_tx(controller, &controller_phy, node, &node_phy, &clock, SX126X_IRQ_RX_DONE);
	assert_status(node, true, false, 0); /* Three-second flush is still pending at JOIN. */
	clock.now_us = 4000001U;
	assert(rt_network_runtime_tick(node) == 0);
	assert_status(node, true, true, 0);
	{
		struct network_beacon forged_body = { .frame_number = 2,
			.contention_ms = NETWORK_CONTENTION_MS,
			.downlink_ms = NETWORK_DEFAULT_DOWNLINK_MS };
		struct network_frame forged = { 0 };
		uint8_t body[NETWORK_FRAME_MAX_PAYLOAD], wire[NETWORK_FRAME_MAX_BYTES];
		size_t body_length, wire_length;
		uint64_t controller_nonce = status_u64(node, "network_controller_boot_nonce");
		assert(network_beacon_encode(&forged_body, body, sizeof(body), &body_length) == 0);
		forged.type = NETWORK_FRAME_BEACON;
		forged.source = NETWORK_CONTROLLER_ID;
		forged.destination = NETWORK_BROADCAST_ID;
		forged.sequence = 2;
		forged.network_id = 77;
		forged.source_boot_nonce = controller_nonce + 1U;
		forged.controller_boot_nonce = controller_nonce + 1U;
		forged.payload_length = (uint16_t)body_length;
		memcpy(forged.payload, body, body_length);
		assert(network_frame_encode(&forged, node_key, wire, sizeof(wire), &wire_length) == 0);
		memcpy(node_phy.rx, wire, wire_length);
		node_phy.rx_length = wire_length;
		assert(rt_network_runtime_on_irq(node, SX126X_IRQ_RX_DONE, clock.now_us) == 0);
		assert(status_u64(node, "network_controller_boot_nonce") == controller_nonce);
		assert_status(node, true, true, 0);
	}
	{
		uint8_t raw_write[RT_COMMAND_WRITE_CHUNK];
		unsigned char base64[64];
		size_t base64_length;
		struct blob_attr *host_fields[__HOST_RESULT_MAX] = {};
		memset(raw_write, 0x5a, sizeof(raw_write));
		assert(mbedtls_base64_encode(base64, sizeof(base64) - 1U,
			&base64_length, raw_write, sizeof(raw_write)) == 0);
		base64[base64_length] = '\0';
		blob_buf_init(&write_payload, BLOBMSG_TYPE_TABLE);
		blobmsg_add_string(&write_payload, "data", (const char *)base64);
		blob_buf_init(&host_result, BLOBMSG_TYPE_TABLE);
		assert(controller_host->callback(controller_host->context, "serial.write",
			request_id, 1, write_payload.head, &host_result) == 0);
		blobmsg_parse(host_result_policy, __HOST_RESULT_MAX, host_fields,
			blobmsg_data(host_result.head), blobmsg_len(host_result.head));
		assert(host_fields[HOST_ACCEPTED] && blobmsg_get_u8(host_fields[HOST_ACCEPTED]));
		assert(host_fields[HOST_PENDING] && blobmsg_get_u8(host_fields[HOST_PENDING]));
		blob_buf_free(&host_result);
	}

	clock.now_us = 4000001U;
	assert(rt_network_runtime_tick(controller) == 0);
	assert(controller_phy.tx_length > 0);
	inject_tx(controller, &controller_phy, node, &node_phy, &clock, SX126X_IRQ_RX_DONE);

	clock.now_us = 4000001U +
		(uint64_t)(NETWORK_FRAME_MS - 100U) * 1000U;
	assert(rt_network_runtime_tick(node) == 0);
	assert(node_phy.cad_count >= 2); /* Authenticated SLOT_REQUEST uses only contention. */
	assert(rt_network_runtime_on_irq(node, SX126X_IRQ_CAD_DONE, clock.now_us) == 0);
	assert(node_phy.tx_length > 0);
	clock.now_us += 10000;
	inject_tx(node, &node_phy, controller, &controller_phy, &clock, SX126X_IRQ_RX_DONE);

	clock.now_us = 4000001U + (uint64_t)NETWORK_FRAME_MS * 1000U;
	assert(rt_network_runtime_tick(controller) == 0);
	assert(controller_phy.tx_length > 0);
	inject_tx(controller, &controller_phy, node, &node_phy, &clock, SX126X_IRQ_RX_DONE);
	if (controller_phy.tx_length)
		inject_tx(controller, &controller_phy, node, &node_phy, &clock, SX126X_IRQ_RX_DONE);
	clock.now_us += 1000;
	assert(rt_network_runtime_tick(node) == 0);
	clock.now_us += (uint64_t)(NETWORK_DEFAULT_DOWNLINK_MS + NETWORK_GUARD_MS - 1U) * 1000U;
	assert(rt_network_runtime_tick(node) == 0);
	assert(node_phy.tx_length > 0); /* Granted DATA fragment. */
	clock.now_us += 50000;
	inject_tx(node, &node_phy, controller, &controller_phy, &clock, SX126X_IRQ_RX_DONE);
	assert_status(controller, false, false, 18); /* Accepted log is held for host delivery. */

	clock.now_us = 4000001U + (uint64_t)NETWORK_FRAME_MS * 2U * 1000U;
	assert(rt_network_runtime_tick(controller) == 0);
	assert(controller_phy.tx_length > 0);
	inject_tx(controller, &controller_phy, node, &node_phy, &clock, SX126X_IRQ_RX_DONE);
	assert_status(node, true, false, 0); /* Beacon ACK retires the retained block. */
	{
		struct rt_command_result partial = {};
		struct network_frame response = {};
		uint8_t uuid[RT_COMMAND_UUID_BYTES], response_payload[32], encoded[NETWORK_FRAME_MAX_BYTES];
		size_t response_length, encoded_length;
		struct blob_attr *host_fields[__HOST_RESULT_MAX] = {};
		assert(rt_command_uuid_parse(request_id, uuid) == 0);
		memcpy(partial.request_uuid, uuid, sizeof(uuid));
		partial.kind = RT_COMMAND_UART_WRITE;
		partial.chunk_index = 0;
		partial.status = EIO;
		partial.written = 10;
		assert(rt_command_result_encode(&partial, response_payload,
			sizeof(response_payload), &response_length) == 0);
		response.type = NETWORK_FRAME_COMMAND_RESPONSE;
		response.source = NETWORK_FIRST_NODE_ID;
		response.destination = NETWORK_CONTROLLER_ID;
		response.sequence = (uint32_t)status_u64(node, "network_tx_sequence") + 1U;
		response.network_id = 77;
		response.source_boot_nonce = status_u64(node, "network_boot_nonce");
		response.controller_boot_nonce = status_u64(controller, "network_boot_nonce");
		response.payload_length = (uint16_t)response_length;
		memcpy(response.payload, response_payload, response_length);
		assert(network_frame_encode(&response, node_key, encoded, sizeof(encoded),
			&encoded_length) == 0);
		memcpy(controller_phy.rx, encoded, encoded_length);
		controller_phy.rx_length = encoded_length;
		assert(rt_network_runtime_on_irq(controller, SX126X_IRQ_RX_DONE,
			clock.now_us) == 0);
		blob_buf_init(&host_result, BLOBMSG_TYPE_TABLE);
		assert(controller_host->callback(controller_host->context, "serial.write",
			request_id, 1, write_payload.head, &host_result) == 0);
		blobmsg_parse(host_result_policy, __HOST_RESULT_MAX, host_fields,
			blobmsg_data(host_result.head), blobmsg_len(host_result.head));
		assert(host_fields[HOST_ACCEPTED] && !blobmsg_get_u8(host_fields[HOST_ACCEPTED]));
		assert(host_fields[HOST_PENDING] && !blobmsg_get_u8(host_fields[HOST_PENDING]));
		assert(host_fields[HOST_STATUS] && blobmsg_get_u32(host_fields[HOST_STATUS]) == EIO);
		assert(host_fields[HOST_WRITTEN] && blobmsg_get_u32(host_fields[HOST_WRITTEN]) == 10);
		blob_buf_free(&host_result);
	}

	rt_network_runtime_stop(node);
	rt_network_runtime_stop(controller);
	blob_buf_free(&write_payload);
	uloop_done();
	test_late_join_does_not_overlap_beacon();
	test_real_uloop_timer_dispatch();
	test_missed_beacon_rejoins();
	test_reboot_join_clears_partial_reassembly();
	test_retry_gap_freezes_and_promotes_next_range();
	test_controller_accepts_two_gaps_then_data();
	test_old_authenticated_beacon_nonce_is_rejected();
	test_node_host_service_is_controller_only();
	test_iperf_busy_start_keeps_active_and_completion_uuid();
	test_demand_lease_expires_across_frame_rollover();
	return 0;
}
