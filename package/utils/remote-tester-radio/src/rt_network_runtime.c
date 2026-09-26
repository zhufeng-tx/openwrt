/* SPDX-License-Identifier: GPL-2.0-only */
#define _GNU_SOURCE
#include "rt_network_runtime.h"

#include "host/rt_host_auth.h"
#include "host/rt_host_server.h"
#include "network/network.h"
#include "rt_command.h"
#include "radio_linux.h"
#include "rt_ip_offload.h"
#include "vendor/sx126x/sx126x.h"

#include <errno.h>
#include <ctype.h>
#include <fcntl.h>
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>
#include <libubox/uloop.h>
#include <libubox/utils.h>
#include <mbedtls/base64.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#define RT_NETWORK_CAPTURE_BYTES NETWORK_MAX_SERIAL_BLOCK
#define RT_NETWORK_FLUSH_MS NETWORK_BLOCK_FLUSH_MS
#define RT_NETWORK_MAX_NODES NETWORK_MAX_NODES
#define RT_NETWORK_MAX_LINE 256U
#define RT_NETWORK_DEMAND_LEASE_FRAMES 2U

struct rt_registry_entry {
	uint8_t eui[8];
	uint8_t key[NETWORK_KEY_BYTES];
	uint8_t node_id;
	bool joined;
	uint64_t boot_nonce;
	uint32_t last_seen_frame;
	uint32_t requested_airtime_us;
	uint32_t demand_expiry_frame;
};

struct rt_tx_block {
	bool active;
	uint32_t stream_id;
	uint16_t block_id;
	uint32_t raw_offset;
	uint16_t raw_length;
	uint8_t codec;
	uint8_t count;
	uint8_t attempts[NETWORK_MAX_FRAGMENTS];
	uint32_t acknowledged;
	size_t encoded_length;
	bool via_rf;
	bool ip_pending;
	uint8_t raw[NETWORK_MAX_SERIAL_BLOCK];
	uint8_t encoded[NETWORK_MAX_COMPRESSED_BLOCK];
	struct network_fragment fragments[NETWORK_MAX_FRAGMENTS];
};

struct rt_delivery_cursor {
	bool initialized;
	uint32_t stream_id;
	uint16_t block_id;
	uint32_t next_offset;
};

struct rt_pending_delivery {
	bool active;
	uint32_t stream_id;
	uint16_t block_id;
	uint32_t raw_offset;
	uint32_t received_bitmap;
	uint16_t raw_length;
	uint8_t raw[NETWORK_MAX_SERIAL_BLOCK];
};

struct rt_host_request_entry {
	bool used;
	bool active;
	bool awaiting;
	char request_id[37];
	uint8_t node_id;
	uint8_t attempt;
	uint8_t next_chunk;
	uint8_t command_count;
	uint8_t status;
	uint32_t sent_frame;
	uint16_t written;
	struct rt_command commands[RT_COMMAND_MAX_CHUNKS];
};

struct rt_pending_command_result {
	bool used;
	uint32_t sent_frame;
	struct rt_command_result result;
};

struct rt_network_runtime {
	struct rt_network_config config;
	struct rt_host_server *host;
	struct rt_ip_server *ip_server;
	struct rt_ip_client *ip_client;
	struct rt_command_agent *command_agent;
	struct uloop_fd serial_fd;
	struct uloop_timeout frame_timer;
	struct uloop_timeout flush_timer;
	struct uloop_timeout grant_timer;
	struct uloop_timeout contention_timer;
	struct uloop_timeout sync_timer;
	struct network_scheduler scheduler;
	struct network_replay_table replay;
	struct network_replay_table beacon_replay;
	struct network_node_link node;
	struct network_reassembler reassembler;
	struct network_queue queue;
	struct network_beacon beacon;
	struct network_ack_entry acknowledgements[NETWORK_MAX_ACK_ENTRIES];
	struct rt_delivery_cursor delivery[NETWORK_MAX_NODES];
	struct rt_pending_delivery pending_delivery[NETWORK_MAX_NODES];
	struct rt_host_request_entry host_requests[64];
	struct rt_pending_command_result command_results[16];
	uint8_t pending_command_ack[NETWORK_MAX_NODES][RT_COMMAND_UUID_BYTES + 1U];
	bool command_ack_pending[NETWORK_MAX_NODES];
	uint8_t pending_gap_ack[NETWORK_MAX_NODES][9];
	bool gap_ack_pending[NETWORK_MAX_NODES];
	uint8_t *queue_storage;
	size_t queue_storage_length;
	uint8_t beacon_key[NETWORK_KEY_BYTES];
	uint8_t node_key[NETWORK_KEY_BYTES];
	uint8_t node_eui[8];
	struct rt_registry_entry registry[RT_NETWORK_MAX_NODES];
	uint8_t registry_count;
	uint8_t node_id;
	uint8_t capture[RT_NETWORK_CAPTURE_BYTES];
	size_t capture_length;
	struct rt_tx_block tx_block;
	uint32_t tx_sequence;
	uint32_t frame_number;
	uint32_t stream_id;
	uint16_t block_id;
	uint32_t raw_offset;
	uint32_t gap_from;
	uint32_t gap_to;
	uint32_t gap_stream_id;
	uint8_t gap_reason;
	uint32_t next_gap_from;
	uint32_t next_gap_to;
	uint32_t next_gap_stream_id;
	uint8_t next_gap_reason;
	uint64_t boot_nonce;
	uint64_t frame_start_us;
	uint64_t contention_start_us;
	uint64_t downlink_deadline_us;
	uint64_t last_serial_flush_us;
	uint64_t last_irq_us;
	uint64_t frame_due_us;
	uint64_t flush_due_us;
	uint64_t grant_due_us;
	uint64_t contention_due_us;
	uint64_t sync_due_us;
	int serial_fd_number;
	uint16_t serial_command_length;
	uint8_t serial_command[NETWORK_MAX_SERIAL_BLOCK];
	size_t next_grant;
	uint32_t contention_frame;
	uint64_t contention_frame_start_us;
	uint32_t contention_attempt;
	uint32_t sent_frame_bitmap;
	uint32_t sent_frame_number;
	uint32_t iperf_grant_used_frame;
	uint32_t iperf_event_sent_frame;
	uint8_t active_iperf_test[RT_COMMAND_UUID_BYTES];
	uint8_t iperf_event_uuid[RT_COMMAND_UUID_BYTES];
	uint16_t beacon_command_sequence;
	uint16_t last_beacon_command_sequence[NETWORK_MAX_NODES];
	bool beacon_command_seen[NETWORK_MAX_NODES];
	int beacon_command_request_index;
	uint8_t tx_type;
	uint8_t tx_destination;
	uint8_t tx_ack_kind;
	bool tx_active;
	bool cad_active;
	bool joined;
	bool initialized;
	bool ip_healthy;
	bool ip_state_known;
	bool beacon_replay_ready;
	bool iperf_event_pending;
	uint8_t iperf_event_status;
	bool gap_pending;
	bool gap_before_queue;
	bool gap_in_flight;
	bool next_gap_pending;
	uint32_t gap_sent_frame;
	bool serial_eof;
	int last_error;
};

static uint64_t monotonic_us(void)
{
	struct timespec now;
	if (clock_gettime(CLOCK_MONOTONIC, &now))
		return 0;
	return (uint64_t)now.tv_sec * 1000000ULL + (uint64_t)now.tv_nsec / 1000ULL;
}

static uint64_t runtime_now(struct rt_network_runtime *runtime)
{
	if (runtime && runtime->config.clock_ops && runtime->config.clock_ops->now_us)
		return runtime->config.clock_ops->now_us(runtime->config.clock_context ?
			runtime->config.clock_context : runtime->config.io_context);
	return monotonic_us();
}

enum rt_timer_id { RT_TIMER_FRAME, RT_TIMER_FLUSH, RT_TIMER_GRANT,
	RT_TIMER_CONTENTION, RT_TIMER_SYNC };

static int runtime_timer_set(struct rt_network_runtime *runtime, enum rt_timer_id id,
	unsigned int delay_ms)
{
	struct uloop_timeout *timer;
	uint64_t *deadline;
	switch (id) {
	case RT_TIMER_FRAME: timer = &runtime->frame_timer; deadline = &runtime->frame_due_us; break;
	case RT_TIMER_FLUSH: timer = &runtime->flush_timer; deadline = &runtime->flush_due_us; break;
	case RT_TIMER_GRANT: timer = &runtime->grant_timer; deadline = &runtime->grant_due_us; break;
	case RT_TIMER_CONTENTION: timer = &runtime->contention_timer; deadline = &runtime->contention_due_us; break;
	case RT_TIMER_SYNC: timer = &runtime->sync_timer; deadline = &runtime->sync_due_us; break;
	default: return -EINVAL;
	}
	*deadline = runtime_now(runtime) + (uint64_t)delay_ms * 1000ULL;
	if (!*deadline)
		*deadline = 1;
	if (uloop_timeout_set(timer, delay_ms)) {
		*deadline = 0;
		return -EIO;
	}
	return 0;
}

static void runtime_timer_clear(struct rt_network_runtime *runtime, enum rt_timer_id id)
{
	switch (id) {
	case RT_TIMER_FRAME: runtime->frame_due_us = 0; break;
	case RT_TIMER_FLUSH: runtime->flush_due_us = 0; break;
	case RT_TIMER_GRANT: runtime->grant_due_us = 0; break;
	case RT_TIMER_CONTENTION: runtime->contention_due_us = 0; break;
	case RT_TIMER_SYNC: runtime->sync_due_us = 0; break;
	}
}

static int random_u64(uint64_t *value)
{
	uint8_t bytes[sizeof(*value)];
	int fd;
	size_t used = 0;
	if (!value)
		return -EINVAL;
	fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -errno;
	while (used < sizeof(bytes)) {
		ssize_t count = read(fd, bytes + used, sizeof(bytes) - used);
		if (count < 0 && errno == EINTR)
			continue;
		if (count <= 0) {
			int error = count == 0 ? -EIO : -errno;
			close(fd);
			return error;
		}
		used += (size_t)count;
	}
	close(fd);
	memcpy(value, bytes, sizeof(*value));
	memset(bytes, 0, sizeof(bytes));
	if (!*value)
		*value = 1;
	return 0;
}

static int parse_hex(const char *text, size_t chars, uint8_t *output, size_t output_len,
	bool lowercase_only)
{
	size_t i;
	if (!text || !output || chars != output_len * 2 || strlen(text) != chars)
		return -EINVAL;
	for (i = 0; i < output_len; i++) {
		unsigned char a = (unsigned char)text[i * 2];
		unsigned char b = (unsigned char)text[i * 2 + 1];
		int high = a >= '0' && a <= '9' ? a - '0' :
			(!lowercase_only && a >= 'A' && a <= 'F') ? a - 'A' + 10 :
			(a >= 'a' && a <= 'f') ? a - 'a' + 10 : -1;
		int low = b >= '0' && b <= '9' ? b - '0' :
			(!lowercase_only && b >= 'A' && b <= 'F') ? b - 'A' + 10 :
			(b >= 'a' && b <= 'f') ? b - 'a' + 10 : -1;
		if (high < 0 || low < 0)
			return -EINVAL;
		output[i] = (uint8_t)((high << 4) | low);
	}
	return 0;
}

static int load_registry(struct rt_network_runtime *runtime)
{
	char line[RT_NETWORK_MAX_LINE];
	struct stat st;
	FILE *file;
	uint8_t count = 0;
	int fd;
	if (!runtime->config.node_registry_path)
		return -EINVAL;
	fd = open(runtime->config.node_registry_path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
	if (fd < 0)
		return -errno;
	if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_uid != 0 ||
	    (st.st_mode & 0077) != 0 || st.st_size > 4096) {
		close(fd);
		return -EACCES;
	}
	file = fdopen(fd, "r");
	if (!file) {
		int error = -errno;
		close(fd);
		return error;
	}
	while (fgets(line, sizeof(line), file)) {
		char eui[17], key[65], extra;
		struct rt_registry_entry entry = {};
		bool has_newline = strchr(line, '\n') != NULL;
		size_t i;
		if (!has_newline && !feof(file)) {
			fclose(file);
			return -E2BIG;
		}
		line[strcspn(line, "\r\n")] = '\0';
		for (i = 0; isspace((unsigned char)line[i]); i++) {
			/* Skip leading whitespace before comments and entries. */
		}
		if (!line[i] || line[i] == '#')
			continue;
		if (sscanf(line + i, "%16s %64s %c", eui, key, &extra) != 2 || count >= RT_NETWORK_MAX_NODES ||
		    parse_hex(eui, 16, entry.eui, sizeof(entry.eui), true) ||
		    parse_hex(key, 64, entry.key, sizeof(entry.key), true)) {
			fclose(file);
			return -EINVAL;
		}
		{
			uint8_t any = 0, all_ff = 0xff;
			for (i = 0; i < sizeof(entry.eui); i++) {
				any |= entry.eui[i];
				all_ff &= entry.eui[i];
			}
			if (!any || all_ff == 0xff) {
				fclose(file);
				return -EINVAL;
			}
		}
		for (i = 0; i < count; i++)
			if (!memcmp(runtime->registry[i].eui, entry.eui, sizeof(entry.eui))) {
				fclose(file);
				return -EEXIST;
			}
		entry.node_id = (uint8_t)(count + NETWORK_FIRST_NODE_ID);
		runtime->registry[count++] = entry;
	}
	if (ferror(file)) {
		int error = -errno;
		fclose(file);
		return error;
	}
	fclose(file);
	runtime->registry_count = count;
	return 0;
}

static struct rt_registry_entry *registry_by_eui(struct rt_network_runtime *runtime,
	const uint8_t eui[8])
{
	uint8_t i;
	for (i = 0; i < runtime->registry_count; i++)
		if (!memcmp(runtime->registry[i].eui, eui, 8))
			return &runtime->registry[i];
	return NULL;
}

static struct rt_registry_entry *registry_by_id(struct rt_network_runtime *runtime,
	uint8_t node_id)
{
	uint8_t i;
	for (i = 0; i < runtime->registry_count; i++)
		if (runtime->registry[i].node_id == node_id)
			return &runtime->registry[i];
	return NULL;
}

static int open_serial(const char *path)
{
	struct termios term;
	int fd;
	if (!path || !path[0])
		return -EINVAL;
	fd = open(path, O_RDWR | O_NOCTTY | O_NONBLOCK | O_CLOEXEC);
	if (fd < 0)
		return -errno;
	if (tcgetattr(fd, &term)) {
		int error = -errno;
		close(fd);
		return error;
	}
	cfmakeraw(&term);
	term.c_cflag |= CLOCAL | CREAD;
	if (cfsetispeed(&term, B115200) || cfsetospeed(&term, B115200) || tcsetattr(fd, TCSANOW, &term)) {
		int error = -errno;
		close(fd);
		return error;
	}
	return fd;
}

static void frame_timer_cb(struct uloop_timeout *timer);
static void flush_timer_cb(struct uloop_timeout *timer);
static void grant_timer_cb(struct uloop_timeout *timer);
static void contention_timer_cb(struct uloop_timeout *timer);
static void serial_cb(struct uloop_fd *watcher, unsigned int events);
static void maybe_schedule_contention(struct rt_network_runtime *runtime, uint64_t now_us);
static int host_request(void *context, const char *type, const char *request_id,
	uint8_t node_id, struct blob_attr *payload, struct blob_buf *result);
static void execute_rf_command(struct rt_network_runtime *runtime,
	const struct network_frame *frame);
static int ip_lookup(void *context, const uint8_t eui[RT_IP_EUI_BYTES],
	uint8_t key[RT_IP_KEY_BYTES], uint8_t *node_id);
static int ip_receive(void *context, uint8_t node_id, const struct rt_ip_block *block,
	uint32_t *next_offset);
static void ip_acknowledge(void *context, uint32_t stream_id, uint16_t block_id,
	uint32_t next_offset);
static void ip_state_changed(void *context, bool healthy);
static void iperf_event(void *context, const uint8_t request_uuid[RT_COMMAND_UUID_BYTES],
	int exit_status);
static int deliver_raw_block(struct rt_network_runtime *runtime, uint8_t node_id,
	uint32_t stream_id, uint16_t block_id, uint32_t offset, const uint8_t *raw,
	size_t raw_length);

static uint32_t radio_airtime_us(const struct radio_config *profile, size_t payload_length)
{
	uint64_t numerator, denominator, payload_symbols, symbol_x4, bandwidth_hz;
	int64_t coded_bits;
	uint32_t sf, cr, de;
	if (!profile || !profile->bandwidth_khz || profile->spreading_factor < 6 ||
	    profile->spreading_factor > 12 || profile->coding_rate < 5 ||
	    profile->coding_rate > 8 || payload_length > NETWORK_FRAME_MAX_BYTES)
		return UINT32_MAX;
	sf = profile->spreading_factor;
	/* Semtech's payload-symbol multiplier is coding rate 5..8 for 4/5..4/8. */
	cr = profile->coding_rate;
	bandwidth_hz = (uint64_t)profile->bandwidth_khz * 1000U;
	de = radio_ldro_required(sf, profile->bandwidth_khz) ? 1U : 0U;
	coded_bits = 8 * (int64_t)payload_length - 4 * (int64_t)sf + 28 + 16;
	denominator = 4U * (sf - 2U * de);
	if (coded_bits <= 0)
		payload_symbols = 8;
	else
		payload_symbols = 8U + ((uint64_t)coded_bits + denominator - 1U) /
			denominator * cr;
	symbol_x4 = 4U * (8U + payload_symbols) + 17U;
	numerator = (1ULL << sf) * 1000000ULL * symbol_x4;
	return (uint32_t)((numerator + bandwidth_hz * 4U - 1U) /
		(bandwidth_hz * 4U));
}

static int validate_network_airtime(const struct radio_config *profile)
{
	uint32_t max_frame_airtime = radio_airtime_us(profile, NETWORK_FRAME_MAX_BYTES);
	uint32_t join_airtime = radio_airtime_us(profile, NETWORK_FRAME_OVERHEAD + 8U);
	uint32_t join_response_airtime = radio_airtime_us(profile, NETWORK_FRAME_OVERHEAD + 9U);
	uint64_t required_us;
	if (max_frame_airtime == UINT32_MAX || join_airtime == UINT32_MAX ||
	    join_response_airtime == UINT32_MAX)
		return -EINVAL;
	/* Beacon, one full granted packet, guards, reserved downlink, and contention tail. */
	required_us = 2ULL * max_frame_airtime +
		(uint64_t)(NETWORK_DEFAULT_DOWNLINK_MS + NETWORK_CONTENTION_MS +
		2U * NETWORK_GUARD_MS) * 1000ULL;
	if (required_us > (uint64_t)NETWORK_FRAME_MS * 1000ULL)
		return -ERANGE;
	/* JOIN and assigned-ID response must fit sequentially in the contention tail. */
	required_us = (uint64_t)join_airtime + join_response_airtime +
		2ULL * NETWORK_GUARD_MS * 1000ULL;
	return required_us <= (uint64_t)NETWORK_CONTENTION_MS * 1000ULL ? 0 : -ERANGE;
}

static int start_rx(struct rt_network_runtime *runtime)
{
	int error;
	if (!runtime || (!runtime->config.radio && !runtime->config.phy_ops))
		return -EINVAL;
	if (runtime->config.phy_ops && runtime->config.phy_ops->start_receive)
		error = runtime->config.phy_ops->start_receive(runtime->config.io_context,
			NETWORK_FRAME_MAX_BYTES, true);
	else
		error = radio_linux_start_receive(runtime->config.radio, NETWORK_FRAME_MAX_BYTES, true);
	if (error)
		runtime->last_error = error;
	return error;
}

static int transmit_frame(struct rt_network_runtime *runtime, struct network_frame *frame,
	const uint8_t key[NETWORK_KEY_BYTES])
{
	uint8_t encoded[NETWORK_FRAME_MAX_BYTES];
	size_t encoded_length;
	int error;
	if (!runtime || !frame || !key)
		return -EINVAL;
	if (!runtime->config.transmit_enabled)
		return -EACCES;
	if (runtime->tx_active)
		return -EBUSY;
	frame->sequence = ++runtime->tx_sequence;
	error = network_frame_encode(frame, key, encoded, sizeof(encoded), &encoded_length);
	if (error)
		return error;
	if (runtime->config.phy_ops && runtime->config.phy_ops->start_transmit)
		error = runtime->config.phy_ops->start_transmit(runtime->config.io_context,
			encoded, encoded_length);
	else
		error = radio_linux_start_transmit(runtime->config.radio, encoded, encoded_length);
	if (!error) {
		runtime->tx_active = true;
		runtime->tx_type = frame->type;
		runtime->tx_destination = frame->destination;
		runtime->tx_ack_kind = frame->type == NETWORK_FRAME_ACK &&
			frame->payload_length == 9U && frame->payload[0] == 1U ? 1U : 0U;
	} else {
		runtime->last_error = error;
	}
	memset(encoded, 0, sizeof(encoded));
	return error;
}

static int send_payload(struct rt_network_runtime *runtime, uint8_t type, uint8_t source,
	uint8_t destination, const uint8_t *payload, size_t payload_length,
	const uint8_t key[NETWORK_KEY_BYTES])
{
	struct network_frame frame = {};
	if (!runtime || payload_length > sizeof(frame.payload) ||
	    (payload_length && !payload))
		return -EINVAL;
	frame.type = type;
	frame.source = source;
	frame.destination = destination;
	frame.network_id = runtime->config.network_id;
	frame.source_boot_nonce = runtime->config.role == RT_NETWORK_CONTROLLER ?
		runtime->boot_nonce : runtime->node.node_boot_nonce;
	frame.controller_boot_nonce = runtime->config.role == RT_NETWORK_CONTROLLER ?
		runtime->boot_nonce : runtime->node.controller_boot_nonce;
	frame.payload_length = (uint16_t)payload_length;
	if (payload_length)
		memcpy(frame.payload, payload, payload_length);
	return transmit_frame(runtime, &frame, key);
}

static int publish_serial_block(struct rt_network_runtime *runtime, uint8_t node_id,
	uint32_t stream_id, uint16_t block_id, uint32_t offset, const uint8_t *bytes,
	size_t length)
{
	struct blob_buf event = {};
	void *payload;
	unsigned char encoded[RT_NETWORK_CAPTURE_BYTES * 2U];
	char *json;
	size_t encoded_length;
	int error;
	if (!runtime->host || !bytes || !length || length > RT_NETWORK_CAPTURE_BYTES)
		return -EINVAL;
	error = mbedtls_base64_encode(encoded, sizeof(encoded), &encoded_length, bytes, length);
	if (error)
		return -EIO;
	if (encoded_length >= sizeof(encoded))
		return -EOVERFLOW;
	encoded[encoded_length] = '\0';
	blob_buf_init(&event, 0);
	blobmsg_add_u32(&event, "version", 1);
	blobmsg_add_string(&event, "type", "serial.log");
	blobmsg_add_u32(&event, "nodeId", node_id);
	blobmsg_add_u64(&event, "streamEpoch", stream_id);
	blobmsg_add_u32(&event, "offset", offset);
	blobmsg_add_u32(&event, "blockId", block_id);
	blobmsg_add_u32(&event, "rawOffset", offset);
	payload = blobmsg_open_table(&event, "payload");
	blobmsg_add_u32(&event, "rawLength", (uint32_t)length);
	blobmsg_add_string(&event, "data", (const char *)encoded);
	blobmsg_close_table(&event, payload);
	json = blobmsg_format_json(event.head, true);
	if (!json) {
		blob_buf_free(&event);
		return -ENOMEM;
	}
	error = rt_host_server_publish(runtime->host, json);
	free(json);
	blob_buf_free(&event);
	memset(encoded, 0, sizeof(encoded));
	return error;
}

static int publish_stream_gap(struct rt_network_runtime *runtime, uint8_t node_id,
	uint32_t stream_id, bool exact, uint32_t from_offset, uint32_t to_offset,
	const char *reason)
{
	struct blob_buf event = {};
	void *payload;
	char *json;
	int error;
	if (!runtime->host || !reason)
		return -ENOTCONN;
	blob_buf_init(&event, 0);
	blobmsg_add_u32(&event, "version", 1);
	blobmsg_add_string(&event, "type", "stream.gap");
	blobmsg_add_u32(&event, "nodeId", node_id);
	blobmsg_add_u64(&event, "streamEpoch", stream_id);
	payload = blobmsg_open_table(&event, "payload");
	blobmsg_add_string(&event, "reason", reason);
	if (exact) {
		blobmsg_add_u32(&event, "fromOffset", from_offset);
		blobmsg_add_u32(&event, "toOffset", to_offset);
	}
	blobmsg_close_table(&event, payload);
	json = blobmsg_format_json(event.head, true);
	if (!json) {
		blob_buf_free(&event);
		return -ENOMEM;
	}
	error = rt_host_server_publish(runtime->host, json);
	free(json);
	blob_buf_free(&event);
	return error;
}

static void put_u16(uint8_t *out, uint16_t value)
{
	out[0] = (uint8_t)value;
	out[1] = (uint8_t)(value >> 8);
}

static void put_u32(uint8_t *out, uint32_t value)
{
	out[0] = (uint8_t)value;
	out[1] = (uint8_t)(value >> 8);
	out[2] = (uint8_t)(value >> 16);
	out[3] = (uint8_t)(value >> 24);
}

static uint16_t get_u16(const uint8_t *in)
{
	return (uint16_t)in[0] | ((uint16_t)in[1] << 8);
}

static uint32_t get_u32(const uint8_t *in)
{
	return (uint32_t)in[0] | ((uint32_t)in[1] << 8) |
		((uint32_t)in[2] << 16) | ((uint32_t)in[3] << 24);
}

static int deliver_raw_block(struct rt_network_runtime *runtime, uint8_t node_id,
	uint32_t stream_id, uint16_t block_id, uint32_t offset, const uint8_t *raw,
	size_t raw_length)
{
	struct rt_delivery_cursor *cursor;
	uint8_t record[NETWORK_MAX_SERIAL_BLOCK + 13U];
	int error;
	if (!runtime || runtime->config.role != RT_NETWORK_CONTROLLER ||
	    node_id < NETWORK_FIRST_NODE_ID || node_id > NETWORK_MAX_ID || !raw ||
	    !raw_length || raw_length > NETWORK_MAX_SERIAL_BLOCK ||
	    raw_length > UINT16_MAX - 12U)
		return -EINVAL;
	cursor = &runtime->delivery[node_id - NETWORK_FIRST_NODE_ID];
	if (cursor->initialized && cursor->stream_id != stream_id) {
		if (runtime->queue.used) {
			record[0] = 2;
			put_u32(record + 1, cursor->stream_id);
			error = network_queue_push(&runtime->queue, node_id, record, 5U);
		} else {
			error = publish_stream_gap(runtime, node_id, cursor->stream_id, false,
				0, 0, "node_reboot_unknown_tail");
			if (error) {
				record[0] = 2;
				put_u32(record + 1, cursor->stream_id);
				error = network_queue_push(&runtime->queue, node_id, record, 5U);
			}
		}
		if (error)
			return error;
		cursor->stream_id = stream_id;
		cursor->next_offset = 0;
		cursor->block_id = 0;
	}
	if (cursor->initialized) {
		uint64_t end = (uint64_t)offset + raw_length;
		if (end <= cursor->next_offset)
			return 0;
		if (offset != cursor->next_offset)
			return -EILSEQ;
	}
	error = runtime->queue.used ? -ENOTCONN :
		publish_serial_block(runtime, node_id, stream_id, block_id, offset, raw, raw_length);
	if (error) {
		record[0] = 0;
		put_u32(record + 1, stream_id);
		put_u16(record + 5, block_id);
		put_u32(record + 7, offset);
		put_u16(record + 11, (uint16_t)raw_length);
		memcpy(record + 13, raw, raw_length);
		error = network_queue_push(&runtime->queue, node_id, record, raw_length + 13U);
		memset(record, 0, sizeof(record));
		if (error)
			return error;
	}
	cursor->initialized = true;
	cursor->stream_id = stream_id;
	cursor->block_id = block_id;
	cursor->next_offset = offset + (uint32_t)raw_length;
	return 0;
}

static int deliver_gap_block(struct rt_network_runtime *runtime, uint8_t node_id,
	uint32_t stream_id, uint32_t from_offset, uint32_t to_offset, uint8_t reason)
{
	struct rt_delivery_cursor *cursor;
	uint8_t record[14];
	uint32_t current_offset, missing_from;
	const char *reason_text = reason == 1U ? "rf_retry_exhausted" :
		reason == 2U ? "rf_retry_exhausted_with_following_bytes" : "serial_queue_overflow";
	int error;
	if (!runtime || runtime->config.role != RT_NETWORK_CONTROLLER ||
	    node_id < NETWORK_FIRST_NODE_ID || node_id > NETWORK_MAX_ID ||
	    to_offset <= from_offset)
		return -EINVAL;
	cursor = &runtime->delivery[node_id - NETWORK_FIRST_NODE_ID];
	if (cursor->initialized && cursor->stream_id != stream_id) {
		error = runtime->queue.used ? -ENOTCONN :
			publish_stream_gap(runtime, node_id, cursor->stream_id, false,
				0, 0, "node_reboot_unknown_tail");
		if (error) {
			record[0] = 2;
			put_u32(record + 1, cursor->stream_id);
			error = network_queue_push(&runtime->queue, node_id, record, 5U);
			if (error)
				return error;
		}
		cursor->stream_id = stream_id;
		cursor->next_offset = 0;
		cursor->initialized = true;
	}
	current_offset = cursor->initialized ? cursor->next_offset : 0U;
	if (to_offset <= current_offset)
		return 0;
	if (from_offset > current_offset)
		return -EILSEQ;
	/* A lost DATA ACK can leave the cursor inside this consolidated GAP. */
	missing_from = current_offset;
	if (!runtime->queue.used)
		error = publish_stream_gap(runtime, node_id, stream_id, true,
			missing_from, to_offset, reason_text);
	else
		error = -ENOTCONN;
	if (error) {
		record[0] = 1;
		put_u32(record + 1, stream_id);
		put_u32(record + 5, missing_from);
		put_u32(record + 9, to_offset);
		record[13] = reason;
		error = network_queue_push(&runtime->queue, node_id, record, sizeof(record));
		if (error)
			return error;
	}
	cursor->initialized = true;
	cursor->stream_id = stream_id;
	cursor->next_offset = to_offset;
	return 0;
}

static void publish_iperf_event(struct rt_network_runtime *runtime, uint8_t node_id,
	const uint8_t test_id[RT_COMMAND_UUID_BYTES], uint8_t status)
{
	struct blob_buf event = {};
	void *payload;
	char test_id_text[37], *json;
	rt_command_uuid_format(test_id, test_id_text);
	blob_buf_init(&event, 0);
	blobmsg_add_u32(&event, "version", 1);
	blobmsg_add_string(&event, "type", "iperf.event");
	blobmsg_add_u32(&event, "nodeId", node_id);
	payload = blobmsg_open_table(&event, "payload");
	blobmsg_add_string(&event, "testId", test_id_text);
	blobmsg_add_string(&event, "state", status ? "failed" : "completed");
	if (status)
		blobmsg_add_string(&event, "message", strerror(status));
	blobmsg_close_table(&event, payload);
	json = blobmsg_format_json(event.head, true);
	if (json) {
		(void)rt_host_server_publish(runtime->host, json);
		free(json);
	}
	blob_buf_free(&event);
}

static void process_status_frame(struct rt_network_runtime *runtime,
	const struct network_frame *frame, struct rt_registry_entry *peer)
{
	uint8_t ack[RT_COMMAND_UUID_BYTES + 1U];
	uint8_t gap_ack[9];
	int error;
	if (runtime->config.role != RT_NETWORK_CONTROLLER || !peer ||
	    frame->destination != NETWORK_CONTROLLER_ID)
		return;
	if (frame->payload_length == 14U && frame->payload[0] == 1U && frame->payload[13] <= 2U) {
		uint32_t stream_id = get_u32(frame->payload + 1);
		uint32_t from_offset = get_u32(frame->payload + 5);
		uint32_t to_offset = get_u32(frame->payload + 9);
		error = deliver_gap_block(runtime, peer->node_id, stream_id,
			from_offset, to_offset, frame->payload[13]);
		if (error)
			return;
		memset(&runtime->reassembler.by_source[peer->node_id],
			0, sizeof(runtime->reassembler.by_source[0]));
		gap_ack[0] = 1U;
		put_u32(gap_ack + 1, stream_id);
		put_u32(gap_ack + 5, to_offset);
		memcpy(runtime->pending_gap_ack[peer->node_id - 1U], gap_ack, sizeof(gap_ack));
		runtime->gap_ack_pending[peer->node_id - 1U] = true;
		return;
	}
	if (frame->payload_length == 18U && frame->payload[0] == 0x49U) {
		publish_iperf_event(runtime, peer->node_id, frame->payload + 1,
			frame->payload[17]);
		memcpy(ack, frame->payload + 1, RT_COMMAND_UUID_BYTES);
		ack[RT_COMMAND_UUID_BYTES] = 0x49U;
		memcpy(runtime->pending_command_ack[peer->node_id - 1U], ack, sizeof(ack));
		runtime->command_ack_pending[peer->node_id - 1U] = true;
	}
}

static void flush_host_queue(struct rt_network_runtime *runtime)
{
	uint8_t record[NETWORK_MAX_SERIAL_BLOCK + 13U], node_id;
	size_t length = 0, dropped_length = 0;
	int error;
	if (!runtime->host || !rt_host_server_has_subscriber(runtime->host))
		return;
	for (;;) {
		error = network_queue_peek(&runtime->queue, &node_id, record, sizeof(record), &length);
		if (error)
			break;
		if (node_id < NETWORK_FIRST_NODE_ID || node_id > NETWORK_MAX_ID || !length) {
			error = -EBADMSG;
		} else if (record[0] == 0 && length >= 13U &&
			get_u16(record + 11) == length - 13U) {
			error = publish_serial_block(runtime, node_id, get_u32(record + 1),
				get_u16(record + 5), get_u32(record + 7), record + 13, length - 13U);
		} else if (record[0] == 1 && length == 14U && record[13] <= 2U) {
			const char *reason = record[13] == 1U ? "rf_retry_exhausted" :
				record[13] == 2U ? "transport_retry_and_queue_overflow" :
				"serial_queue_overflow";
			error = publish_stream_gap(runtime, node_id, get_u32(record + 1), true,
				get_u32(record + 5), get_u32(record + 9), reason);
		} else if (record[0] == 2 && length == 5U) {
			error = publish_stream_gap(runtime, node_id, get_u32(record + 1), false,
				0, 0, "node_reboot_unknown_tail");
		} else {
			error = -EBADMSG;
		}
		if (error)
			break;
		error = network_queue_drop_front(&runtime->queue, &node_id, &dropped_length);
		if (error || dropped_length != length) {
			runtime->last_error = error ? error : -EIO;
			break;
		}
		memset(record, 0, sizeof(record));
	}
}

static int send_join_response(struct rt_network_runtime *runtime,
	struct rt_registry_entry *entry, uint64_t node_boot_nonce)
{
	struct network_frame frame = {};
	uint8_t payload[9];
	uint64_t now = runtime_now(runtime), frame_end;
	uint32_t airtime;
	int error;
	error = network_join_response_payload_encode(entry->node_id, node_boot_nonce, payload);
	if (error)
		return error;
	airtime = radio_airtime_us(&runtime->config.radio_profile,
		NETWORK_FRAME_OVERHEAD + sizeof(payload));
	frame_end = runtime->frame_start_us + NETWORK_FRAME_MS * 1000ULL;
	if (airtime == UINT32_MAX || now + airtime + NETWORK_GUARD_MS * 1000ULL > frame_end)
		return -ETIMEDOUT;
	frame.type = NETWORK_FRAME_JOIN_RESPONSE;
	frame.source = NETWORK_CONTROLLER_ID;
	frame.destination = NETWORK_UNASSIGNED_NODE_ID;
	frame.network_id = runtime->config.network_id;
	frame.source_boot_nonce = runtime->boot_nonce;
	frame.controller_boot_nonce = runtime->boot_nonce;
	frame.payload_length = sizeof(payload);
	memcpy(frame.payload, payload, sizeof(payload));
	return transmit_frame(runtime, &frame, entry->key);
}

static int handle_join(struct rt_network_runtime *runtime, const uint8_t *packet,
	size_t packet_length, const struct network_frame *peeked)
{
	struct rt_registry_entry *entry;
	struct network_frame frame;
	int error;
	if (peeked->type != NETWORK_FRAME_JOIN || peeked->source != NETWORK_UNASSIGNED_NODE_ID ||
	    peeked->payload_length != sizeof(runtime->node_eui) ||
	    peeked->destination != NETWORK_CONTROLLER_ID)
		return -EBADMSG;
	entry = registry_by_eui(runtime, peeked->payload);
	if (!entry)
		return -ENOENT;
	error = network_frame_decode(packet, packet_length, entry->key, &runtime->replay, &frame);
	if (error)
		return error;
	if (entry->joined && entry->boot_nonce != frame.source_boot_nonce)
		memset(&runtime->reassembler.by_source[entry->node_id],
			0, sizeof(runtime->reassembler.by_source[0]));
	if (entry->joined && entry->boot_nonce != frame.source_boot_nonce) {
		entry->requested_airtime_us = 0;
		entry->demand_expiry_frame = 0;
	}
	error = network_replay_bind_node(&runtime->replay, entry->node_id,
		frame.source_boot_nonce, frame.sequence);
	if (error)
		return error;
	entry->joined = true;
	entry->boot_nonce = frame.source_boot_nonce;
	entry->last_seen_frame = runtime->frame_number;
	return send_join_response(runtime, entry, frame.source_boot_nonce);
}

static int decode_for_runtime(struct rt_network_runtime *runtime, const uint8_t *packet,
	size_t packet_length, struct network_frame *peeked, struct network_frame *decoded,
	struct rt_registry_entry **peer)
{
	const uint8_t *key;
	int error;
	*peer = NULL;
	error = network_frame_peek(packet, packet_length, peeked);
	if (error)
		return error;
	if (runtime->config.role == RT_NETWORK_CONTROLLER) {
		if (peeked->type == NETWORK_FRAME_JOIN)
			return -EINPROGRESS;
		*peer = registry_by_id(runtime, peeked->source);
		if (!*peer || !(*peer)->joined || (*peer)->boot_nonce != peeked->source_boot_nonce)
			return -EACCES;
		key = (*peer)->key;
	} else if (peeked->type == NETWORK_FRAME_BEACON) {
		key = runtime->beacon_key;
	} else {
		key = runtime->node_key;
	}
	return network_frame_decode(packet, packet_length, key, &runtime->replay, decoded);
}

static int build_node_block(struct rt_network_runtime *runtime)
{
	uint8_t raw[NETWORK_MAX_SERIAL_BLOCK];
	uint8_t encoded[NETWORK_MAX_COMPRESSED_BLOCK];
	struct network_fragment fragments[NETWORK_MAX_FRAGMENTS];
	uint8_t destination, codec;
	size_t raw_length, encoded_length, fragment_count;
	int error;
	if (runtime->tx_block.active || runtime->config.role != RT_NETWORK_NODE ||
	    (runtime->gap_pending && runtime->gap_before_queue))
		return 0;
	error = network_queue_pop(&runtime->queue, &destination, raw, sizeof(raw), &raw_length);
	if (error)
		return error == -EAGAIN ? 0 : error;
	if (destination != NETWORK_CONTROLLER_ID || !raw_length || raw_length > UINT16_MAX)
		return -EBADMSG;
	error = network_block_encode(raw, raw_length, encoded, sizeof(encoded), &encoded_length, &codec);
	if (!error)
		error = network_block_fragment(runtime->stream_id, runtime->block_id,
			runtime->raw_offset, (uint16_t)raw_length, codec, encoded, encoded_length,
			fragments, sizeof(fragments) / sizeof(fragments[0]), &fragment_count);
	if (error) {
		(void)network_queue_push(&runtime->queue, NETWORK_CONTROLLER_ID, raw, raw_length);
		memset(raw, 0, sizeof(raw));
		memset(encoded, 0, sizeof(encoded));
		return error;
	}
	memset(&runtime->tx_block, 0, sizeof(runtime->tx_block));
	runtime->tx_block.active = true;
	runtime->tx_block.stream_id = runtime->stream_id;
	runtime->tx_block.block_id = runtime->block_id;
	runtime->tx_block.raw_offset = runtime->raw_offset;
	runtime->tx_block.raw_length = (uint16_t)raw_length;
	runtime->tx_block.codec = codec;
	runtime->tx_block.count = (uint8_t)fragment_count;
	runtime->tx_block.encoded_length = encoded_length;
	runtime->tx_block.via_rf = !runtime->ip_client ||
		(runtime->ip_state_known && !runtime->ip_healthy) ||
		(runtime->command_agent && rt_command_agent_iperf_active(runtime->command_agent));
	memcpy(runtime->tx_block.raw, raw, raw_length);
	memcpy(runtime->tx_block.encoded, encoded, encoded_length);
	memcpy(runtime->tx_block.fragments, fragments,
		fragment_count * sizeof(runtime->tx_block.fragments[0]));
	memset(raw, 0, sizeof(raw));
	memset(encoded, 0, sizeof(encoded));
	memset(fragments, 0, sizeof(fragments));
	return 0;
}

static void try_ip_block(struct rt_network_runtime *runtime)
{
	struct rt_ip_block block;
	int error;
	if (!runtime || !runtime->ip_client || !runtime->tx_block.active ||
	    runtime->tx_block.ip_pending || runtime->tx_block.via_rf ||
	    (runtime->command_agent && rt_command_agent_iperf_active(runtime->command_agent)) ||
	    !rt_ip_client_healthy(runtime->ip_client))
		return;
	memset(&block, 0, sizeof(block));
	block.stream_id = runtime->tx_block.stream_id;
	block.block_id = runtime->tx_block.block_id;
	block.raw_offset = runtime->tx_block.raw_offset;
	block.raw_length = runtime->tx_block.raw_length;
	block.codec = runtime->tx_block.codec;
	block.encoded = runtime->tx_block.encoded;
	block.encoded_length = runtime->tx_block.encoded_length;
	error = rt_ip_client_send(runtime->ip_client, &block);
	if (!error)
		runtime->tx_block.ip_pending = true;
	else if (error != -EBUSY && error != -ENOTCONN) {
		runtime->last_error = error;
		if (runtime->ip_state_known && !runtime->ip_healthy)
			runtime->tx_block.via_rf = true;
	}
}

static void apply_acknowledgements(struct rt_network_runtime *runtime,
	const struct network_beacon *beacon)
{
	uint8_t i;
	for (i = 0; i < beacon->acknowledgement_count; i++) {
		const struct network_ack_entry *ack = &beacon->acknowledgements[i];
		uint32_t complete;
		if (!runtime->tx_block.active || ack->node_id != runtime->node.node_id ||
		    ack->stream_id != runtime->tx_block.stream_id ||
		    ack->block_id != runtime->tx_block.block_id)
			continue;
		runtime->tx_block.acknowledged |= ack->received_bitmap;
		complete = runtime->tx_block.count == 32 ? UINT32_MAX :
			((1U << runtime->tx_block.count) - 1U);
		if ((runtime->tx_block.acknowledged & complete) == complete) {
			if (runtime->tx_block.ip_pending && runtime->ip_client)
				rt_ip_client_cancel_pending(runtime->ip_client,
					runtime->tx_block.stream_id, runtime->tx_block.block_id);
			runtime->raw_offset += runtime->tx_block.raw_length;
			runtime->block_id++;
			memset(&runtime->tx_block, 0, sizeof(runtime->tx_block));
			(void)build_node_block(runtime);
			try_ip_block(runtime);
		}
	}
}

static int process_data(struct rt_network_runtime *runtime, const struct network_frame *frame)
{
	struct network_fragment fragment;
	uint8_t raw[NETWORK_MAX_SERIAL_BLOCK];
	struct network_ack_entry *ack = NULL;
	struct rt_pending_delivery *pending;
	size_t raw_length = 0;
	uint32_t raw_offset = 0, received = 0, missing = 0;
	int result, error;
	if (!runtime || !frame || frame->type != NETWORK_FRAME_DATA ||
	    runtime->config.role != RT_NETWORK_CONTROLLER ||
	    frame->destination != NETWORK_CONTROLLER_ID)
		return -EINVAL;
	error = network_fragment_unpack(frame->payload, frame->payload_length, &fragment);
	if (error)
		return error;
	if (frame->source < NETWORK_FIRST_NODE_ID || frame->source > NETWORK_MAX_ID)
		return -EBADMSG;
	ack = &runtime->acknowledgements[frame->source - 1U];
	pending = &runtime->pending_delivery[frame->source - 1U];
	if (pending->active) {
		if (pending->stream_id != fragment.stream_id || pending->block_id != fragment.block_id)
			return -EBUSY;
		ack->node_id = frame->source;
		ack->stream_id = fragment.stream_id;
		ack->block_id = fragment.block_id;
		error = deliver_raw_block(runtime, frame->source, pending->stream_id,
			pending->block_id, pending->raw_offset, pending->raw, pending->raw_length);
		if (!error) {
			ack->received_bitmap = pending->received_bitmap;
			memset(pending, 0, sizeof(*pending));
		} else {
			ack->received_bitmap = pending->received_bitmap & ~(1U << fragment.index);
		}
		return error;
	}
	result = network_reassembler_add(&runtime->reassembler, frame->source, &fragment,
		raw, sizeof(raw), &raw_length, &raw_offset, &received, &missing);
	ack->node_id = frame->source;
	ack->stream_id = fragment.stream_id;
	ack->block_id = fragment.block_id;
	ack->received_bitmap = received;
	if (result < 0)
		return result;
	error = 0;
	if (result == 1) {
		error = deliver_raw_block(runtime, frame->source, fragment.stream_id,
			fragment.block_id, raw_offset, raw, raw_length);
		if (error) {
			pending->active = true;
			pending->stream_id = fragment.stream_id;
			pending->block_id = fragment.block_id;
			pending->raw_offset = raw_offset;
			pending->received_bitmap = received;
			pending->raw_length = (uint16_t)raw_length;
			memcpy(pending->raw, raw, raw_length);
			ack->received_bitmap = received & ~(1U << fragment.index);
		}
	}
	memset(raw, 0, sizeof(raw));
	(void)missing;
	return error;
}

static void flush_pending_delivery(struct rt_network_runtime *runtime)
{
	uint8_t i;
	for (i = 0; i < NETWORK_MAX_NODES; i++) {
		struct rt_pending_delivery *pending = &runtime->pending_delivery[i];
		struct network_ack_entry *ack = &runtime->acknowledgements[i];
		if (!pending->active)
			continue;
		if (deliver_raw_block(runtime, (uint8_t)(i + NETWORK_FIRST_NODE_ID),
		    pending->stream_id, pending->block_id, pending->raw_offset,
		    pending->raw, pending->raw_length))
			continue;
		ack->node_id = (uint8_t)(i + NETWORK_FIRST_NODE_ID);
		ack->stream_id = pending->stream_id;
		ack->block_id = pending->block_id;
		ack->received_bitmap = pending->received_bitmap;
		memset(pending, 0, sizeof(*pending));
	}
}

static int process_beacon(struct rt_network_runtime *runtime,
	const struct network_frame *frame, uint64_t irq_us)
{
	struct network_beacon beacon;
	uint32_t beacon_airtime, sync_timeout_ms;
	int error = 0;
	if (network_beacon_decode(frame->payload, frame->payload_length, &beacon))
		return -EBADMSG;
	if (runtime->contention_frame != beacon.frame_number)
		runtime->contention_attempt = 0;
	runtime->contention_frame = beacon.frame_number;
	runtime->frame_number = beacon.frame_number;
	runtime->contention_frame_start_us = irq_us;
	runtime->contention_start_us = irq_us +
		(NETWORK_FRAME_MS - NETWORK_CONTENTION_MS) * 1000ULL;
	if (runtime->node.joined && runtime->node.state == NETWORK_NODE_SYNCED &&
	    beacon.frame_number != runtime->node.synced_frame + 1U) {
		(void)network_node_check_sync(&runtime->node, beacon.frame_number);
		uloop_timeout_cancel(&runtime->sync_timer);
		runtime_timer_clear(runtime, RT_TIMER_SYNC);
		(void)network_node_begin_join(&runtime->node);
		runtime->joined = false;
		runtime->node_id = NETWORK_UNASSIGNED_NODE_ID;
		network_replay_begin_join(&runtime->replay);
	}
	if (runtime->node.joined) {
		error = network_node_observe_beacon(&runtime->node, frame,
			runtime->contention_frame_start_us);
		if (!error) {
			beacon_airtime = radio_airtime_us(&runtime->config.radio_profile,
				NETWORK_FRAME_MAX_BYTES);
			sync_timeout_ms = NETWORK_FRAME_MS + NETWORK_GUARD_MS +
				(beacon_airtime == UINT32_MAX ? NETWORK_GUARD_MS :
				 (beacon_airtime + 999U) / 1000U);
			apply_acknowledgements(runtime, &beacon);
			runtime->frame_start_us = runtime->contention_frame_start_us;
			runtime->sent_frame_number = beacon.frame_number;
			runtime->sent_frame_bitmap = 0;
			(void)runtime_timer_set(runtime, RT_TIMER_SYNC, sync_timeout_ms);
			(void)build_node_block(runtime);
			try_ip_block(runtime);
			runtime->next_grant = 0;
			(void)runtime_timer_set(runtime, RT_TIMER_GRANT, 1U);
		}
	}
	if (runtime->node.joined && beacon.has_command &&
	    beacon.command.target_node_id == runtime->node.node_id &&
	    !network_beacon_command_verify(&beacon, runtime->config.network_id,
		runtime->node.controller_boot_nonce, runtime->node_key)) {
		uint8_t index = (uint8_t)(runtime->node.node_id - NETWORK_FIRST_NODE_ID);
		uint16_t delta = (uint16_t)(beacon.command.sequence -
			runtime->last_beacon_command_sequence[index]);
		if (!runtime->beacon_command_seen[index] || (delta && delta < 0x8000U)) {
			struct network_frame command_frame = {};
			command_frame.type = NETWORK_FRAME_COMMAND;
			command_frame.source = NETWORK_CONTROLLER_ID;
			command_frame.destination = runtime->node.node_id;
			command_frame.payload_length = beacon.command.length;
			memcpy(command_frame.payload, beacon.command.bytes, beacon.command.length);
			runtime->last_beacon_command_sequence[index] = beacon.command.sequence;
			runtime->beacon_command_seen[index] = true;
			execute_rf_command(runtime, &command_frame);
		}
	}
	if (runtime->config.role == RT_NETWORK_NODE && beacon.contention_ms)
		maybe_schedule_contention(runtime, irq_us);
	return error;
}

static struct rt_host_request_entry *find_host_request(struct rt_network_runtime *runtime,
	const char *request_id)
{
	size_t i;
	for (i = 0; i < sizeof(runtime->host_requests) / sizeof(runtime->host_requests[0]); i++)
		if (runtime->host_requests[i].used &&
	    !strcmp(runtime->host_requests[i].request_id, request_id))
			return &runtime->host_requests[i];
	return NULL;
}

static struct rt_host_request_entry *new_host_request(struct rt_network_runtime *runtime)
{
	size_t i;
	for (i = 0; i < sizeof(runtime->host_requests) / sizeof(runtime->host_requests[0]); i++)
		if (!runtime->host_requests[i].used || !runtime->host_requests[i].active)
			return &runtime->host_requests[i];
	return NULL;
}

static struct rt_pending_command_result *pending_result(struct rt_network_runtime *runtime,
	const uint8_t uuid[RT_COMMAND_UUID_BYTES], uint8_t chunk_index, bool create)
{
	struct rt_pending_command_result *free_entry = NULL;
	size_t i;
	for (i = 0; i < sizeof(runtime->command_results) / sizeof(runtime->command_results[0]); i++) {
		struct rt_pending_command_result *entry = &runtime->command_results[i];
		if (entry->used && entry->result.chunk_index == chunk_index &&
		    !memcmp(entry->result.request_uuid, uuid, RT_COMMAND_UUID_BYTES))
			return entry;
		if (!entry->used && !free_entry)
			free_entry = entry;
	}
	return create ? free_entry : NULL;
}

static void publish_host_command_result(struct rt_network_runtime *runtime,
	const char *type, const char *request_id, uint8_t status, uint16_t written)
{
	struct blob_buf event = {};
	void *payload;
	char *json;
	if (!runtime->host || !type || !request_id)
		return;
	blob_buf_init(&event, 0);
	blobmsg_add_u32(&event, "version", 1);
	blobmsg_add_string(&event, "type", type);
	blobmsg_add_string(&event, "requestId", request_id);
	payload = blobmsg_open_table(&event, "payload");
	blobmsg_add_u32(&event, "status", status);
	blobmsg_add_u32(&event, "written", written);
	blobmsg_close_table(&event, payload);
	json = blobmsg_format_json(event.head, true);
	if (json) {
		(void)rt_host_server_publish(runtime->host, json);
		free(json);
	}
	blob_buf_free(&event);
}

static void publish_node_status(struct rt_network_runtime *runtime, uint8_t node_id,
	const char *request_id)
{
	struct rt_registry_entry *entry = registry_by_id(runtime, node_id);
	struct blob_buf event = {};
	void *payload;
	char eui[17], hostname[32], *json;
	static const char digits[] = "0123456789abcdef";
	size_t i;
	if (!runtime->host || !entry)
		return;
	for (i = 0; i < 8; i++) {
		eui[i * 2] = digits[entry->eui[i] >> 4];
		eui[i * 2 + 1] = digits[entry->eui[i] & 0x0f];
	}
	eui[16] = '\0';
	snprintf(hostname, sizeof(hostname), "mt7628-node-%u", node_id);
	blob_buf_init(&event, 0);
	blobmsg_add_u32(&event, "version", 1);
	blobmsg_add_string(&event, "type", "node.status");
	if (request_id)
		blobmsg_add_string(&event, "requestId", request_id);
	blobmsg_add_u32(&event, "nodeId", node_id);
	payload = blobmsg_open_table(&event, "payload");
	blobmsg_add_u32(&event, "nodeId", node_id);
	blobmsg_add_string(&event, "mac", eui);
	blobmsg_add_string(&event, "eui", eui);
	blobmsg_add_string(&event, "hostname", hostname);
	blobmsg_add_string(&event, "ipv4", "");
	blobmsg_add_string(&event, "state", entry->joined ? "online" : "offline");
	blobmsg_add_u8(&event, "joined", entry->joined);
	blobmsg_add_u32(&event, "lastSeen", entry->last_seen_frame);
	blobmsg_add_u32(&event, "queueBytes",
		(uint32_t)network_queue_demand_bytes(&runtime->queue, node_id));
	blobmsg_close_table(&event, payload);
	json = blobmsg_format_json(event.head, true);
	if (json) {
		(void)rt_host_server_publish(runtime->host, json);
		free(json);
	}
	blob_buf_free(&event);
}

static void process_command_response(struct rt_network_runtime *runtime,
	const struct network_frame *frame, struct rt_registry_entry *peer)
{
	struct rt_command_result result;
	struct rt_host_request_entry *request;
	char request_id[37];
	uint8_t ack[RT_COMMAND_UUID_BYTES + 1U];
	int error;
	if (runtime->config.role != RT_NETWORK_CONTROLLER || !peer ||
	    frame->destination != NETWORK_CONTROLLER_ID)
		return;
	error = rt_command_result_decode(frame->payload, frame->payload_length, &result);
	if (error)
		return;
	memcpy(ack, result.request_uuid, RT_COMMAND_UUID_BYTES);
	ack[RT_COMMAND_UUID_BYTES] = result.chunk_index;
	memcpy(runtime->pending_command_ack[peer->node_id - 1U], ack, sizeof(ack));
	runtime->command_ack_pending[peer->node_id - 1U] = true;
	rt_command_uuid_format(result.request_uuid, request_id);
	request = find_host_request(runtime, request_id);
	if (!request || !request->active || request->node_id != peer->node_id ||
	    request->next_chunk != result.chunk_index || request->commands[result.chunk_index].kind != result.kind)
		return;
	request->awaiting = false;
	request->attempt = 0;
	request->written = (uint16_t)(request->written + result.written);
	if (result.status) {
		const char *type = result.kind == RT_COMMAND_IPERF_START ||
			result.kind == RT_COMMAND_IPERF_STOP ? "iperf.result" :
			result.kind == RT_COMMAND_STATUS ? "node.status.result" : "serial.write.result";
		publish_host_command_result(runtime, type, request_id, result.status, request->written);
		request->status = result.status;
		request->active = false;
		return;
	}
	request->next_chunk++;
	if (request->next_chunk >= request->command_count) {
		const char *type = result.kind == RT_COMMAND_IPERF_START ||
			result.kind == RT_COMMAND_IPERF_STOP ? "iperf.result" :
			result.kind == RT_COMMAND_STATUS ? "node.status.result" : "serial.write.result";
		if (result.kind == RT_COMMAND_STATUS)
			publish_node_status(runtime, peer->node_id, request_id);
		else
			publish_host_command_result(runtime, type, request_id, 0, request->written);
		request->active = false;
	}
}

static int prepare_beacon_command(struct rt_network_runtime *runtime,
	struct network_beacon *beacon)
{
	size_t i;
	runtime->beacon_command_request_index = -1;
	for (i = 0; i < sizeof(runtime->host_requests) / sizeof(runtime->host_requests[0]); i++) {
		struct rt_host_request_entry *request = &runtime->host_requests[i];
		struct rt_registry_entry *entry;
		uint8_t wire[NETWORK_BEACON_COMMAND_MAX_BYTES];
		size_t wire_length;
		int error;
		if (!request->used || !request->active || request->awaiting ||
		    request->next_chunk >= request->command_count)
			continue;
		entry = registry_by_id(runtime, request->node_id);
		if (!entry || !entry->joined)
			continue;
		error = rt_command_encode(&request->commands[request->next_chunk],
			wire, sizeof(wire), &wire_length);
		if (error || wire_length > NETWORK_BEACON_COMMAND_MAX_BYTES)
			continue;
		beacon->has_command = true;
		beacon->command.target_node_id = request->node_id;
		beacon->command.sequence = ++runtime->beacon_command_sequence;
		beacon->command.length = (uint8_t)wire_length;
		memcpy(beacon->command.bytes, wire, wire_length);
		error = network_beacon_command_sign(&beacon->command,
			runtime->config.network_id, runtime->boot_nonce,
			beacon->frame_number, entry->key, beacon->command.tag);
		memset(wire, 0, sizeof(wire));
		if (error) {
			beacon->has_command = false;
			return error;
		}
		runtime->beacon_command_request_index = (int)i;
		return 0;
	}
	return -ENODATA;
}

static int send_controller_downlink(struct rt_network_runtime *runtime)
{
	uint64_t now = runtime_now(runtime);
	uint64_t deadline = runtime->downlink_deadline_us;
	uint8_t node_id, payload[RT_COMMAND_UUID_BYTES + 1U];
	size_t i;
	if (!runtime->config.transmit_enabled || now >= deadline)
		return -EACCES;
	for (node_id = NETWORK_FIRST_NODE_ID; node_id <= NETWORK_MAX_ID; node_id++) {
		struct rt_registry_entry *entry;
		if (!runtime->gap_ack_pending[node_id - 1U])
			continue;
		entry = registry_by_id(runtime, node_id);
		if (!entry)
			return -ENOENT;
		if (radio_airtime_us(&runtime->config.radio_profile,
		    NETWORK_FRAME_OVERHEAD + sizeof(runtime->pending_gap_ack[node_id - 1U])) + now > deadline)
			return -ETIMEDOUT;
		return send_payload(runtime, NETWORK_FRAME_ACK, NETWORK_CONTROLLER_ID, node_id,
			runtime->pending_gap_ack[node_id - 1U],
			sizeof(runtime->pending_gap_ack[node_id - 1U]), entry->key);
	}
	for (node_id = NETWORK_FIRST_NODE_ID; node_id <= NETWORK_MAX_ID; node_id++) {
		struct rt_registry_entry *entry;
		if (!runtime->command_ack_pending[node_id - 1U])
			continue;
		memcpy(payload, runtime->pending_command_ack[node_id - 1U], sizeof(payload));
		if (radio_airtime_us(&runtime->config.radio_profile,
		    NETWORK_FRAME_OVERHEAD + sizeof(payload)) + now > deadline)
			return -ETIMEDOUT;
		entry = registry_by_id(runtime, node_id);
		if (!entry)
			return -ENOENT;
		return send_payload(runtime, NETWORK_FRAME_ACK, NETWORK_CONTROLLER_ID, node_id,
			payload, sizeof(payload), entry->key);
	}
	if (runtime->beacon_command_request_index >= 0)
		return -ENODATA;
	for (i = 0; i < sizeof(runtime->host_requests) / sizeof(runtime->host_requests[0]); i++) {
		struct rt_host_request_entry *request = &runtime->host_requests[i];
		struct rt_command *command;
		uint8_t wire[NETWORK_FRAME_MAX_PAYLOAD];
		size_t wire_length;
		struct rt_registry_entry *entry;
		int error;
		if (!request->used || !request->active || request->awaiting ||
		    request->next_chunk >= request->command_count)
			continue;
		entry = registry_by_id(runtime, request->node_id);
		if (!entry || !entry->joined)
			return -ENOTCONN;
		command = &request->commands[request->next_chunk];
		error = rt_command_encode(command, wire, sizeof(wire), &wire_length);
		if (error)
			return error;
		if (radio_airtime_us(&runtime->config.radio_profile,
		    NETWORK_FRAME_OVERHEAD + wire_length) + now > deadline)
			return -ETIMEDOUT;
		error = send_payload(runtime, NETWORK_FRAME_COMMAND, NETWORK_CONTROLLER_ID,
			request->node_id, wire, wire_length, entry->key);
		if (!error) {
			request->awaiting = true;
			request->sent_frame = runtime->frame_number;
		}
		memset(wire, 0, sizeof(wire));
		return error;
	}
	return -ENODATA;
}

static void iperf_event(void *context, const uint8_t request_uuid[RT_COMMAND_UUID_BYTES],
	int exit_status)
{
	struct rt_network_runtime *runtime = context;
	char request_id[37];
	if (!runtime || !request_uuid)
		return;
	rt_command_uuid_format(request_uuid, request_id);
	if (runtime->config.role == RT_NETWORK_NODE) {
		memcpy(runtime->iperf_event_uuid, request_uuid, RT_COMMAND_UUID_BYTES);
		runtime->iperf_event_pending = true;
		runtime->iperf_event_status = (uint8_t)(exit_status < 0 ? -exit_status : exit_status);
		if (runtime->ip_client && rt_ip_client_healthy(runtime->ip_client)) {
			bool sent = false;
			size_t i;
			for (i = 0; i < runtime->tx_block.count; i++)
				sent |= runtime->tx_block.attempts[i] != 0;
			if (!sent)
				runtime->tx_block.via_rf = false;
			try_ip_block(runtime);
		}
	} else {
		publish_host_command_result(runtime, "iperf.finished", request_id,
			(uint8_t)(exit_status < 0 ? -exit_status : exit_status), 0);
	}
}

static void command_agent_iperf_event(void *context,
	const uint8_t request_uuid[RT_COMMAND_UUID_BYTES], int exit_status)
{
	iperf_event(context, request_uuid, exit_status);
}

static void record_iperf_start_result(struct rt_network_runtime *runtime,
	const struct rt_command *command, const struct rt_command_result *result)
{
	if (runtime && command && result && command->kind == RT_COMMAND_IPERF_START &&
	    result->status == 0 && command->data_length >= RT_COMMAND_UUID_BYTES)
		memcpy(runtime->active_iperf_test, command->data, RT_COMMAND_UUID_BYTES);
}

static int host_discover(struct rt_network_runtime *runtime, struct blob_buf *result)
{
	void *array = blobmsg_open_array(result, "nodes");
	if (runtime->config.role == RT_NETWORK_CONTROLLER) {
		uint8_t i;
		for (i = 0; i < runtime->registry_count; i++) {
			struct rt_registry_entry *entry = &runtime->registry[i];
			void *node = blobmsg_open_table(result, NULL);
			char eui[17];
			static const char digits[] = "0123456789abcdef";
			size_t j;
			for (j = 0; j < 8; j++) {
				eui[j * 2] = digits[entry->eui[j] >> 4];
				eui[j * 2 + 1] = digits[entry->eui[j] & 0x0f];
			}
			eui[16] = '\0';
			blobmsg_add_u32(result, "nodeId", entry->node_id);
			blobmsg_add_string(result, "mac", eui);
			{
				char hostname[32];
				snprintf(hostname, sizeof(hostname), "mt7628-node-%u", entry->node_id);
				blobmsg_add_string(result, "hostname", hostname);
			}
			blobmsg_add_string(result, "ipv4", "");
			{
				void *capabilities = blobmsg_open_array(result, "capabilities");
				blobmsg_add_string(result, NULL, "serial");
				blobmsg_add_string(result, NULL, "iperf");
				blobmsg_add_string(result, NULL, "lora");
				blobmsg_close_array(result, capabilities);
			}
			blobmsg_add_string(result, "eui", eui);
			blobmsg_add_u8(result, "joined", entry->joined);
			blobmsg_add_u32(result, "lastSeenFrame", entry->last_seen_frame);
			blobmsg_add_u32(result, "lastSeen", entry->last_seen_frame);
			blobmsg_add_string(result, "state", entry->joined ? "online" : "offline");
			{
				void *status = blobmsg_open_table(result, "status");
				blobmsg_add_u8(result, "joined", entry->joined);
				blobmsg_add_u32(result, "queueBytes",
					(uint32_t)network_queue_demand_bytes(&runtime->queue, entry->node_id));
				blobmsg_add_u32(result, "lastSeenFrame", entry->last_seen_frame);
				blobmsg_close_table(result, status);
			}
			blobmsg_close_table(result, node);
		}
	} else if (runtime->config.role == RT_NETWORK_NODE && runtime->node.joined) {
		void *node = blobmsg_open_table(result, NULL);
		char eui[17];
		static const char digits[] = "0123456789abcdef";
		size_t j;
		for (j = 0; j < 8; j++) {
			eui[j * 2] = digits[runtime->node_eui[j] >> 4];
			eui[j * 2 + 1] = digits[runtime->node_eui[j] & 0x0f];
		}
		eui[16] = '\0';
		blobmsg_add_u32(result, "nodeId", runtime->node.node_id);
		blobmsg_add_string(result, "mac", eui);
		blobmsg_add_string(result, "hostname", "mt7628-node-local");
		blobmsg_add_string(result, "ipv4", "");
		{
			void *capabilities = blobmsg_open_array(result, "capabilities");
			blobmsg_add_string(result, NULL, "serial");
			blobmsg_add_string(result, NULL, "iperf");
			blobmsg_add_string(result, NULL, "lora");
			blobmsg_close_array(result, capabilities);
		}
		blobmsg_add_string(result, "eui", eui);
		blobmsg_add_u8(result, "joined", true);
		blobmsg_add_string(result, "state", "online");
		blobmsg_add_u32(result, "lastSeen", runtime->node.last_beacon_frame);
		{
			void *status = blobmsg_open_table(result, "status");
			blobmsg_add_u8(result, "joined", true);
			blobmsg_add_u32(result, "queueBytes", (uint32_t)network_queue_demand_bytes(
				&runtime->queue, NETWORK_CONTROLLER_ID));
			blobmsg_close_table(result, status);
		}
		blobmsg_close_table(result, node);
	}
	blobmsg_close_array(result, array);
	return 0;
}

static bool commands_equal(const struct rt_command *a, const struct rt_command *b,
	size_t count)
{
	size_t i;
	for (i = 0; i < count; i++)
		if (a[i].kind != b[i].kind || a[i].chunk_index != b[i].chunk_index ||
		    a[i].chunk_count != b[i].chunk_count || a[i].data_length != b[i].data_length ||
		    memcmp(a[i].request_uuid, b[i].request_uuid, RT_COMMAND_UUID_BYTES) ||
		    memcmp(a[i].data, b[i].data, a[i].data_length))
			return false;
	return true;
}

static int host_execute_local(struct rt_network_runtime *runtime, const char *request_id,
	const char *type, struct blob_attr *payload, struct blob_buf *result)
{
	struct rt_command commands[RT_COMMAND_MAX_CHUNKS];
	struct rt_command_result command_result;
	size_t count, i;
	uint16_t written = 0;
	int error;
	if (!runtime->command_agent)
		return -ENODEV;
	error = rt_command_prepare_host(type, request_id, payload, commands, &count);
	if (error)
		return error;
	for (i = 0; i < count; i++) {
		error = rt_command_agent_execute(runtime->command_agent, &commands[i], &command_result);
		if (error)
			return error;
		written = (uint16_t)(written + command_result.written);
		if (command_result.status) {
			blobmsg_add_u8(result, "accepted", false);
			blobmsg_add_u32(result, "status", command_result.status);
			blobmsg_add_u32(result, "written", written);
			return 0;
		}
	}
	blobmsg_add_u8(result, "accepted", true);
	blobmsg_add_u32(result, "written", written);
	if (!strcmp(type, "node.status"))
		rt_network_runtime_add_status(runtime, result);
	return 0;
}

static int host_request(void *context, const char *type, const char *request_id,
	uint8_t node_id, struct blob_attr *payload, struct blob_buf *result)
{
	struct rt_network_runtime *runtime = context;
	struct rt_command commands[RT_COMMAND_MAX_CHUNKS];
	struct rt_host_request_entry *entry;
	size_t command_count;
	int error;
	if (!runtime || !type || !request_id || !result)
		return -EINVAL;
	if (!strcmp(type, "node.discover"))
		return host_discover(runtime, result);
	if (runtime->config.role == RT_NETWORK_NODE) {
		if (!runtime->node.joined)
			return -ENOTCONN;
		if (node_id != runtime->node.node_id)
			return -ENOENT;
		return host_execute_local(runtime, request_id, type, payload, result);
	}
	if (runtime->config.role != RT_NETWORK_CONTROLLER || node_id < NETWORK_FIRST_NODE_ID ||
	    node_id > NETWORK_MAX_ID)
		return -EINVAL;
	error = rt_command_prepare_host(type, request_id, payload, commands, &command_count);
	if (error)
		return error;
	entry = find_host_request(runtime, request_id);
	if (entry) {
		if (entry->node_id != node_id || entry->command_count != command_count ||
		    !commands_equal(entry->commands, commands, command_count))
			return -EEXIST;
		blobmsg_add_u8(result, "accepted", entry->status == 0);
		blobmsg_add_u8(result, "pending", entry->active);
		if (entry->status)
			blobmsg_add_u32(result, "status", entry->status);
		blobmsg_add_u32(result, "written", entry->written);
		return 0;
	}
	if (!registry_by_id(runtime, node_id))
		return -ENOENT;
	entry = new_host_request(runtime);
	if (!entry)
		return -ENOSPC;
	memset(entry, 0, sizeof(*entry));
	entry->used = true;
	entry->active = true;
	strncpy(entry->request_id, request_id, sizeof(entry->request_id) - 1U);
	entry->node_id = node_id;
	entry->command_count = (uint8_t)command_count;
	memcpy(entry->commands, commands, command_count * sizeof(commands[0]));
	blobmsg_add_u8(result, "accepted", true);
	blobmsg_add_u8(result, "pending", true);
	blobmsg_add_u32(result, "chunks", (uint32_t)command_count);
	return 0;
}

static void execute_rf_command(struct rt_network_runtime *runtime,
	const struct network_frame *frame)
{
	struct rt_command command;
	struct rt_command_result result;
	struct rt_pending_command_result *pending;
	int error;
	if (!runtime->command_agent || frame->destination != runtime->node.node_id)
		return;
	error = rt_command_decode(frame->payload, frame->payload_length, &command);
	if (error)
		return;
	error = rt_command_agent_execute(runtime->command_agent, &command, &result);
	if (error) {
		memset(&result, 0, sizeof(result));
		memcpy(result.request_uuid, command.request_uuid, sizeof(result.request_uuid));
		result.kind = command.kind;
		result.chunk_index = command.chunk_index;
		result.status = EIO;
	}
	record_iperf_start_result(runtime, &command, &result);
	pending = pending_result(runtime, result.request_uuid, result.chunk_index, true);
	if (!pending) {
		runtime->last_error = -ENOSPC;
		return;
	}
	pending->used = true;
	pending->sent_frame = 0;
	pending->result = result;
}

static void process_command_ack(struct rt_network_runtime *runtime,
	const struct network_frame *frame)
{
	struct rt_pending_command_result *pending;
	if (frame->source != NETWORK_CONTROLLER_ID || frame->destination != runtime->node.node_id)
		return;
	if (frame->payload_length == 9U && frame->payload[0] == 1U && runtime->gap_pending &&
	    runtime->gap_in_flight &&
	    get_u32(frame->payload + 1) == runtime->gap_stream_id &&
	    get_u32(frame->payload + 5) == runtime->gap_to) {
		runtime->raw_offset = runtime->gap_to;
		runtime->block_id++;
		if (runtime->next_gap_pending) {
			runtime->gap_from = runtime->next_gap_from;
			runtime->gap_to = runtime->next_gap_to;
			runtime->gap_stream_id = runtime->next_gap_stream_id;
			runtime->gap_reason = runtime->next_gap_reason;
			runtime->gap_in_flight = false;
			runtime->gap_before_queue = true;
			runtime->gap_sent_frame = 0;
			runtime->next_gap_pending = false;
			runtime->next_gap_from = runtime->next_gap_to =
				runtime->next_gap_stream_id = 0;
			runtime->next_gap_reason = 0;
		} else {
			runtime->gap_pending = false;
			runtime->gap_before_queue = false;
			runtime->gap_in_flight = false;
			runtime->gap_reason = 0;
			runtime->gap_from = runtime->gap_to = runtime->gap_stream_id = 0;
			runtime->gap_sent_frame = 0;
		}
		if (runtime->gap_pending)
			return;
		(void)build_node_block(runtime);
		try_ip_block(runtime);
		return;
	}
	if (frame->payload_length != RT_COMMAND_UUID_BYTES + 1U)
		return;
	if (frame->payload[RT_COMMAND_UUID_BYTES] == 0x49U &&
	    !memcmp(frame->payload, runtime->iperf_event_uuid, RT_COMMAND_UUID_BYTES)) {
		runtime->iperf_event_pending = false;
		return;
	}
	pending = pending_result(runtime, frame->payload, frame->payload[RT_COMMAND_UUID_BYTES], false);
	if (pending)
		memset(pending, 0, sizeof(*pending));
}

static int ip_lookup(void *context, const uint8_t eui[RT_IP_EUI_BYTES],
	uint8_t key[RT_IP_KEY_BYTES], uint8_t *node_id)
{
	struct rt_network_runtime *runtime = context;
	struct rt_registry_entry *entry;
	if (!runtime || !eui || !key || !node_id || runtime->config.role != RT_NETWORK_CONTROLLER)
		return -EINVAL;
	entry = registry_by_eui(runtime, eui);
	if (!entry)
		return -EACCES;
	memcpy(key, entry->key, RT_IP_KEY_BYTES);
	*node_id = entry->node_id;
	return 0;
}

static int ip_receive(void *context, uint8_t node_id, const struct rt_ip_block *block,
	uint32_t *next_offset)
{
	struct rt_network_runtime *runtime = context;
	uint8_t raw[NETWORK_MAX_SERIAL_BLOCK];
	size_t raw_length = 0;
	int error;
	if (!runtime || !block || !next_offset || node_id < NETWORK_FIRST_NODE_ID ||
	    node_id > NETWORK_MAX_ID || !block->encoded || !block->encoded_length ||
	    block->raw_length == 0 || block->raw_length > sizeof(raw))
		return -EINVAL;
	if (block->codec == NETWORK_CODEC_RAW) {
		if (block->encoded_length != block->raw_length)
			return -EBADMSG;
		memcpy(raw, block->encoded, block->raw_length);
		raw_length = block->raw_length;
	} else if (block->codec == NETWORK_CODEC_DEFLATE) {
		error = network_block_decompress(block->encoded, block->encoded_length,
			block->raw_length, raw, sizeof(raw), &raw_length);
		if (error)
			return error;
	} else {
		return -EBADMSG;
	}
	error = deliver_raw_block(runtime, node_id, block->stream_id, block->block_id,
		block->raw_offset, raw, raw_length);
	if (!error)
		*next_offset = block->raw_offset + (uint32_t)raw_length;
	memset(raw, 0, sizeof(raw));
	return error;
}

static void ip_acknowledge(void *context, uint32_t stream_id, uint16_t block_id,
	uint32_t next_offset)
{
	struct rt_network_runtime *runtime = context;
	if (!runtime || !runtime->tx_block.active || !runtime->tx_block.ip_pending ||
	    runtime->tx_block.stream_id != stream_id || runtime->tx_block.block_id != block_id ||
	    next_offset != runtime->tx_block.raw_offset + runtime->tx_block.raw_length)
		return;
	runtime->raw_offset = next_offset;
	runtime->block_id++;
	memset(&runtime->tx_block, 0, sizeof(runtime->tx_block));
	(void)build_node_block(runtime);
	try_ip_block(runtime);
}

static void ip_state_changed(void *context, bool healthy)
{
	struct rt_network_runtime *runtime = context;
	if (!runtime)
		return;
	runtime->ip_state_known = true;
	runtime->ip_healthy = healthy;
	if (runtime->config.role == RT_NETWORK_NODE && runtime->tx_block.active) {
		if (!healthy)
			runtime->tx_block.via_rf = true;
		else {
			bool sent = false;
			size_t i;
			for (i = 0; i < runtime->tx_block.count; i++)
				sent |= runtime->tx_block.attempts[i] != 0;
			if (!sent && !(runtime->command_agent &&
			    rt_command_agent_iperf_active(runtime->command_agent)))
				runtime->tx_block.via_rf = false;
			try_ip_block(runtime);
		}
	}
}

static uint32_t node_requested_airtime(const struct rt_network_runtime *runtime)
{
	size_t bytes = network_queue_demand_bytes(&runtime->queue, NETWORK_CONTROLLER_ID);
	size_t fragments = (bytes + NETWORK_FRAGMENT_DATA_BYTES - 1U) /
		NETWORK_FRAGMENT_DATA_BYTES;
	uint32_t airtime = radio_airtime_us(&runtime->config.radio_profile,
		NETWORK_DATA_FRAME_MAX_BYTES);
	size_t i;
	for (i = 0; i < sizeof(runtime->command_results) / sizeof(runtime->command_results[0]); i++)
		if (runtime->command_results[i].used)
			fragments++;
	if (runtime->iperf_event_pending)
		fragments++;
	if (runtime->gap_pending)
		fragments++;
	if (runtime->tx_block.active && runtime->tx_block.via_rf) {
		uint32_t full = runtime->tx_block.count == 32 ? UINT32_MAX :
			((1U << runtime->tx_block.count) - 1U);
		fragments += (size_t)__builtin_popcount(full & ~runtime->tx_block.acknowledged);
	}
	if (!fragments || airtime == UINT32_MAX)
		return 0;
	if (fragments > UINT32_MAX / airtime)
		return UINT32_MAX;
	{
		uint64_t requested = (uint64_t)fragments * airtime;
		if (runtime->command_agent && rt_command_agent_iperf_active(runtime->command_agent) &&
		    requested > NETWORK_FRAME_MS * 100U)
			requested = NETWORK_FRAME_MS * 100U;
		return requested > UINT32_MAX ? UINT32_MAX : (uint32_t)requested;
	}
}

static uint64_t node_granted_airtime(const struct rt_network_runtime *runtime)
{
	uint64_t airtime = 0;
	uint8_t i;
	if (!runtime || !runtime->node.joined)
		return 0;
	for (i = 0; i < runtime->node.grant_count; i++)
		if (runtime->node.grants[i].node_id == runtime->node.node_id)
			airtime += runtime->node.grants[i].airtime_budget_us;
	return airtime;
}

static int send_contention_frame(struct rt_network_runtime *runtime)
{
	uint8_t payload[4];
	uint32_t demand;
	uint32_t payload_length, airtime;
	uint64_t now = runtime_now(runtime);
	struct network_frame frame;
	int error;
	if (runtime->node.state == NETWORK_NODE_JOINING) {
		payload_length = 8U;
		airtime = radio_airtime_us(&runtime->config.radio_profile,
			NETWORK_FRAME_OVERHEAD + payload_length);
		if (airtime == UINT32_MAX || now + airtime + NETWORK_GUARD_MS * 1000ULL >
		    runtime->contention_frame_start_us + NETWORK_FRAME_MS * 1000ULL)
			return -ETIMEDOUT;
		error = network_node_build_join(&runtime->node, ++runtime->tx_sequence, &frame);
		if (error)
			return error;
		return transmit_frame(runtime, &frame, runtime->node_key);
	}
	if (runtime->node.joined) {
		demand = node_requested_airtime(runtime);
		if (!demand || node_granted_airtime(runtime) >= demand)
			return -ENODATA;
		payload_length = sizeof(payload);
		airtime = radio_airtime_us(&runtime->config.radio_profile,
			NETWORK_FRAME_OVERHEAD + payload_length);
		if (airtime == UINT32_MAX || now + airtime + NETWORK_GUARD_MS * 1000ULL >
		    runtime->contention_frame_start_us + NETWORK_FRAME_MS * 1000ULL)
			return -ETIMEDOUT;
		put_u32(payload, demand);
		return send_payload(runtime, NETWORK_FRAME_SLOT_REQUEST, runtime->node.node_id,
			NETWORK_CONTROLLER_ID, payload, sizeof(payload), runtime->node_key);
	}
	return -ENOTCONN;
}

static void schedule_contention_retry(struct rt_network_runtime *runtime, uint64_t now_us)
{
	uint64_t deadline, remaining;
	uint32_t backoff, random_value, slot_ms;
	if (!runtime->contention_start_us)
		return;
	deadline = runtime->contention_frame_start_us + NETWORK_FRAME_MS * 1000ULL;
	if (now_us >= deadline)
		return;
	remaining = (deadline - now_us) / 1000U;
	if (remaining < 12U)
		return;
	slot_ms = network_contention_slot_time_ms(
		(uint8_t)runtime->config.radio_profile.spreading_factor,
		(uint16_t)runtime->config.radio_profile.bandwidth_khz, 2U);
	if (!slot_ms)
		return;
	random_value = (uint32_t)(runtime->node.node_boot_nonce ^
		((uint64_t)runtime->contention_frame * 0x9e3779b9U) ^
		(++runtime->contention_attempt * 0x85ebca6bU));
	backoff = network_contention_backoff_ms((uint8_t)runtime->contention_attempt,
		random_value, slot_ms, (uint32_t)remaining - 12U);
	(void)runtime_timer_set(runtime, RT_TIMER_CONTENTION, backoff);
}

static void maybe_schedule_contention(struct rt_network_runtime *runtime, uint64_t now_us)
{
	uint64_t deadline, target;
	uint32_t random_value, backoff, slot_ms, demand;
	if (!runtime->config.transmit_enabled || !runtime->contention_start_us)
		return;
	if (runtime->node.joined) {
		demand = node_requested_airtime(runtime);
		if (!demand || node_granted_airtime(runtime) >= demand)
			return;
	}
	deadline = runtime->contention_frame_start_us + NETWORK_FRAME_MS * 1000ULL;
	if (now_us >= deadline)
		return;
	slot_ms = network_contention_slot_time_ms(
		(uint8_t)runtime->config.radio_profile.spreading_factor,
		(uint16_t)runtime->config.radio_profile.bandwidth_khz, 2U);
	if (!slot_ms)
		return;
	random_value = (uint32_t)(runtime->node.node_boot_nonce ^
		((uint64_t)runtime->contention_frame * 0x9e3779b9U) ^ runtime->contention_attempt);
	backoff = network_contention_backoff_ms((uint8_t)runtime->contention_attempt,
		random_value, slot_ms, NETWORK_CONTENTION_MS - 12U);
	target = runtime->contention_start_us + (uint64_t)backoff * 1000U;
	if (target < now_us)
		target = now_us;
	if (target + 12000U < deadline)
		(void)runtime_timer_set(runtime, RT_TIMER_CONTENTION,
			(unsigned int)((target - now_us + 999U) / 1000U));
}

static void process_frame(struct rt_network_runtime *runtime,
	const struct network_frame *frame, struct rt_registry_entry *peer, uint64_t irq_us)
{
	if (runtime->config.role == RT_NETWORK_CONTROLLER) {
		if (frame->destination != NETWORK_CONTROLLER_ID &&
		    frame->destination != NETWORK_BROADCAST_ID)
			return;
		if (frame->type == NETWORK_FRAME_SLOT_REQUEST && peer && frame->payload_length == 4) {
			peer->requested_airtime_us = get_u32(frame->payload);
			peer->last_seen_frame = runtime->frame_number;
			peer->demand_expiry_frame = peer->requested_airtime_us ?
				runtime->frame_number + RT_NETWORK_DEMAND_LEASE_FRAMES : 0;
		} else if (frame->type == NETWORK_FRAME_DATA) {
			if (!process_data(runtime, frame) && peer) {
				if (!peer->requested_airtime_us)
					peer->requested_airtime_us = radio_airtime_us(
						&runtime->config.radio_profile, NETWORK_DATA_FRAME_MAX_BYTES);
				peer->last_seen_frame = runtime->frame_number;
				peer->demand_expiry_frame = runtime->frame_number +
					RT_NETWORK_DEMAND_LEASE_FRAMES;
			}
		} else if (frame->type == NETWORK_FRAME_COMMAND_RESPONSE) {
			process_command_response(runtime, frame, peer);
		} else if (frame->type == NETWORK_FRAME_STATUS) {
			process_status_frame(runtime, frame, peer);
		}
	} else if (runtime->config.role == RT_NETWORK_NODE) {
		if (frame->type == NETWORK_FRAME_BEACON) {
			(void)process_beacon(runtime, frame, irq_us);
		} else if (frame->type == NETWORK_FRAME_JOIN_RESPONSE) {
			if (!network_node_observe_join_response(&runtime->node, frame)) {
				runtime->node_id = runtime->node.node_id;
				runtime->joined = true;
				runtime->frame_number = 0;
			}
		} else if (frame->type == NETWORK_FRAME_COMMAND) {
			execute_rf_command(runtime, frame);
		} else if (frame->type == NETWORK_FRAME_ACK) {
			process_command_ack(runtime, frame);
		} else if (frame->type == NETWORK_FRAME_STATUS) {
			runtime->last_irq_us = irq_us;
		}
	}
}

static int flush_node_capture(struct rt_network_runtime *runtime)
{
	int error;
	if (!runtime->capture_length)
		return 0;
	error = network_queue_push(&runtime->queue, NETWORK_CONTROLLER_ID,
		runtime->capture, runtime->capture_length);
	if (error) {
		runtime->last_error = error;
		return error;
	}
	memset(runtime->capture, 0, runtime->capture_length);
	runtime->capture_length = 0;
	runtime->last_serial_flush_us = runtime_now(runtime);
	(void)build_node_block(runtime);
	try_ip_block(runtime);
	return 0;
}

static int begin_queue_gap(struct rt_network_runtime *runtime, size_t dropped)
{
	uint64_t from, to;
	if (!runtime || !dropped)
		return -EINVAL;
	if (runtime->gap_pending && runtime->gap_in_flight) {
		if (!runtime->next_gap_pending) {
			runtime->next_gap_pending = true;
			runtime->next_gap_stream_id = runtime->gap_stream_id;
			runtime->next_gap_from = runtime->gap_to;
			runtime->next_gap_to = runtime->gap_to;
			runtime->next_gap_reason = runtime->gap_reason;
		}
		if (runtime->next_gap_stream_id != runtime->gap_stream_id ||
		    runtime->next_gap_from != runtime->gap_to ||
		    runtime->next_gap_to < runtime->next_gap_from)
			return -EILSEQ;
		to = (uint64_t)runtime->next_gap_to + dropped;
		if (to > UINT32_MAX)
			return -EOVERFLOW;
		runtime->next_gap_to = (uint32_t)to;
		return 0;
	}
	if (runtime->gap_pending) {
		to = (uint64_t)runtime->gap_to + dropped;
		if (to > UINT32_MAX)
			return -EOVERFLOW;
		runtime->gap_to = (uint32_t)to;
		return 0;
	}
	from = (uint64_t)runtime->raw_offset +
		(runtime->tx_block.active ? runtime->tx_block.raw_length : 0U) +
		network_queue_demand_bytes(&runtime->queue, NETWORK_CONTROLLER_ID) +
		runtime->capture_length;
	to = from + dropped;
	if (to > UINT32_MAX)
		return -EOVERFLOW;
	runtime->gap_pending = true;
	runtime->gap_stream_id = runtime->stream_id;
	runtime->gap_from = (uint32_t)from;
	runtime->gap_to = (uint32_t)to;
	runtime->gap_reason = 0;
	runtime->gap_before_queue = false;
	runtime->gap_in_flight = false;
	runtime->gap_sent_frame = 0;
	return 0;
}

static void append_serial_bytes(struct rt_network_runtime *runtime,
	const uint8_t *bytes, size_t length)
{
	size_t copied = 0;
	if (runtime->gap_pending) {
		int error = begin_queue_gap(runtime, length);
		if (error)
			runtime->last_error = error;
		return;
	}
	while (copied < length) {
		size_t room = sizeof(runtime->capture) - runtime->capture_length;
		size_t chunk = length - copied < room ? length - copied : room;
		if (chunk) {
			memcpy(runtime->capture + runtime->capture_length, bytes + copied, chunk);
			runtime->capture_length += chunk;
			copied += chunk;
		}
		if (runtime->capture_length != sizeof(runtime->capture))
			continue;
		if (!flush_node_capture(runtime))
			continue;
		if (length > copied && begin_queue_gap(runtime, length - copied))
			runtime->last_error = -EOVERFLOW;
		return;
	}
}

static void retry_host_commands(struct rt_network_runtime *runtime)
{
	size_t i;
	for (i = 0; i < sizeof(runtime->host_requests) / sizeof(runtime->host_requests[0]); i++) {
		struct rt_host_request_entry *request = &runtime->host_requests[i];
		if (!request->used || !request->active || !request->awaiting ||
		    runtime->frame_number - request->sent_frame < 2U)
			continue;
		request->awaiting = false;
		if (request->attempt >= NETWORK_MAX_RETRIES) {
			publish_host_command_result(runtime,
				request->commands[request->next_chunk].kind == RT_COMMAND_UART_WRITE ?
					"serial.write.result" : "request.error",
				request->request_id, ETIMEDOUT, request->written);
			request->status = ETIMEDOUT;
			request->active = false;
			continue;
		}
		request->attempt++;
	}
}

static int send_controller_beacon(struct rt_network_runtime *runtime)
{
	struct network_demand demands[NETWORK_MAX_NODES] = {};
	uint8_t payload[NETWORK_FRAME_MAX_PAYLOAD];
	size_t length, grant_count;
	uint8_t i;
	int error;
	memset(&runtime->beacon, 0, sizeof(runtime->beacon));
	runtime->beacon.frame_number = ++runtime->frame_number;
	runtime->beacon.contention_ms = NETWORK_CONTENTION_MS;
	runtime->beacon.downlink_ms = NETWORK_DEFAULT_DOWNLINK_MS;
	for (i = 0; i < runtime->registry_count; i++) {
		struct rt_registry_entry *entry = &runtime->registry[i];
		demands[i].joined = entry->joined;
		if (!entry->requested_airtime_us ||
		    (int32_t)(entry->demand_expiry_frame - runtime->beacon.frame_number) < 0) {
			entry->requested_airtime_us = 0;
			entry->demand_expiry_frame = 0;
		} else {
			demands[i].requested_airtime_us = entry->requested_airtime_us;
		}
	}
	error = network_scheduler_build_grants(&runtime->scheduler,
		runtime->beacon.frame_number, demands,
		radio_airtime_us(&runtime->config.radio_profile, NETWORK_DATA_FRAME_MAX_BYTES),
		runtime->beacon.grants,
		NETWORK_MAX_GRANTS, &grant_count);
	if (error)
		return error;
	runtime->beacon.grant_count = (uint8_t)grant_count;
	for (i = 0; i < NETWORK_MAX_ACK_ENTRIES; i++) {
		if (!runtime->acknowledgements[i].node_id)
			continue;
		runtime->beacon.acknowledgements[runtime->beacon.acknowledgement_count++] =
			runtime->acknowledgements[i];
	}
	(void)prepare_beacon_command(runtime, &runtime->beacon);
	error = network_beacon_encode(&runtime->beacon, payload, sizeof(payload), &length);
	if (error && runtime->beacon.has_command) {
		runtime->beacon.has_command = false;
		runtime->beacon_command_request_index = -1;
		error = network_beacon_encode(&runtime->beacon, payload, sizeof(payload), &length);
	}
	if (error)
		return error;
	runtime->frame_start_us = runtime_now(runtime);
	error = send_payload(runtime, NETWORK_FRAME_BEACON, NETWORK_CONTROLLER_ID,
		NETWORK_BROADCAST_ID, payload, length, runtime->beacon_key);
	if (!error && runtime->beacon_command_request_index >= 0) {
		struct rt_host_request_entry *request =
			&runtime->host_requests[runtime->beacon_command_request_index];
		request->awaiting = true;
		request->sent_frame = runtime->frame_number;
	}
	memset(payload, 0, sizeof(payload));
	return error;
}

static void frame_timer_cb(struct uloop_timeout *timer)
{
	struct rt_network_runtime *runtime = container_of(timer,
		struct rt_network_runtime, frame_timer);
	int error;
	runtime_timer_clear(runtime, RT_TIMER_FRAME);
	if (runtime->config.role != RT_NETWORK_CONTROLLER)
		return;
	if (runtime->tx_active) {
		(void)runtime_timer_set(runtime, RT_TIMER_FRAME, 20U);
		return;
	}
	retry_host_commands(runtime);
	flush_host_queue(runtime);
	flush_pending_delivery(runtime);
	error = send_controller_beacon(runtime);
	if (error) {
		runtime->last_error = error;
		(void)runtime_timer_set(runtime, RT_TIMER_FRAME, NETWORK_FRAME_MS);
	}
}

static int retire_retry_exhausted_block(struct rt_network_runtime *runtime)
{
	uint64_t end;
	size_t queued_bytes;
	bool has_following;
	if (!runtime || !runtime->tx_block.active ||
	    (uint64_t)runtime->tx_block.raw_offset + runtime->tx_block.raw_length > UINT32_MAX)
		return -EINVAL;
	if (runtime->gap_in_flight || runtime->next_gap_pending)
		return -EBUSY;
	if (runtime->gap_pending &&
	    (runtime->gap_before_queue || runtime->gap_stream_id != runtime->tx_block.stream_id))
		return -EILSEQ;
	queued_bytes = network_queue_demand_bytes(&runtime->queue, NETWORK_CONTROLLER_ID);
	end = (uint64_t)runtime->tx_block.raw_offset + runtime->tx_block.raw_length +
		queued_bytes + runtime->capture_length;
	if (runtime->gap_pending && runtime->gap_to > end)
		end = runtime->gap_to;
	if (end > UINT32_MAX)
		return -EOVERFLOW;
	has_following = queued_bytes || runtime->capture_length || runtime->gap_pending;
	/* Retire all intervening bytes with the failed block; preserve an exact range. */
	while (network_queue_demand_bytes(&runtime->queue, NETWORK_CONTROLLER_ID)) {
		uint8_t discarded[NETWORK_MAX_SERIAL_BLOCK], destination;
		size_t discarded_length;
		int error = network_queue_pop(&runtime->queue, &destination,
			discarded, sizeof(discarded), &discarded_length);
		if (error || destination != NETWORK_CONTROLLER_ID)
			return error ? error : -EIO;
		memset(discarded, 0, sizeof(discarded));
	}
	memset(runtime->capture, 0, runtime->capture_length);
	runtime->capture_length = 0;
	runtime->gap_pending = true;
	runtime->gap_in_flight = false;
	runtime->next_gap_pending = false;
	runtime->gap_before_queue = true;
	runtime->gap_reason = has_following ? 2U : 1U;
	runtime->gap_stream_id = runtime->tx_block.stream_id;
	runtime->gap_from = runtime->tx_block.raw_offset;
	runtime->gap_to = (uint32_t)end;
	runtime->gap_sent_frame = 0;
	runtime->next_gap_from = runtime->next_gap_to = runtime->next_gap_stream_id = 0;
	runtime->next_gap_reason = 0;
	if (runtime->tx_block.ip_pending && runtime->ip_client)
		rt_ip_client_cancel_pending(runtime->ip_client,
			runtime->tx_block.stream_id, runtime->tx_block.block_id);
	memset(&runtime->tx_block, 0, sizeof(runtime->tx_block));
	runtime->sent_frame_bitmap = 0;
	runtime->gap_sent_frame = 0;
	runtime->last_error = -ETIMEDOUT;
	return 0;
}

static int send_node_grant_packet(struct rt_network_runtime *runtime,
	const struct network_grant *grant)
{
	uint64_t now = runtime_now(runtime);
	uint32_t airtime;
	size_t i;
	if (!runtime->config.transmit_enabled || !runtime->node.joined || !grant)
		return -EACCES;
	if (runtime->tx_block.active && runtime->tx_block.via_rf) {
		for (i = 0; i < runtime->tx_block.count; i++) {
			if ((runtime->tx_block.acknowledged & (1U << i)) ||
			    network_retry_allowed(runtime->tx_block.attempts[i]))
				continue;
			return retire_retry_exhausted_block(runtime) ? -ETIMEDOUT : -EAGAIN;
		}
	}
	for (i = 0; i < sizeof(runtime->command_results) / sizeof(runtime->command_results[0]); i++) {
		struct rt_pending_command_result *pending = &runtime->command_results[i];
		uint8_t payload[32];
		size_t length;
		int error;
		if (!pending->used || pending->sent_frame == runtime->frame_number)
			continue;
		error = rt_command_result_encode(&pending->result, payload, sizeof(payload), &length);
		if (error)
			return error;
		airtime = radio_airtime_us(&runtime->config.radio_profile,
			NETWORK_FRAME_OVERHEAD + length);
		if (!network_node_tx_window(&runtime->node, runtime->frame_number, now, airtime))
			return -EAGAIN;
		error = send_payload(runtime, NETWORK_FRAME_COMMAND_RESPONSE,
			runtime->node.node_id, NETWORK_CONTROLLER_ID, payload, length, runtime->node_key);
		if (!error) {
			pending->sent_frame = runtime->frame_number;
			if (runtime->command_agent && rt_command_agent_iperf_active(runtime->command_agent))
				runtime->iperf_grant_used_frame = runtime->frame_number;
		}
		return error;
	}
	if (runtime->iperf_event_pending &&
	    (!runtime->command_agent || !rt_command_agent_iperf_active(runtime->command_agent))) {
		uint8_t payload[1 + RT_COMMAND_UUID_BYTES + 1U];
		if (runtime->iperf_event_sent_frame == runtime->frame_number)
			return -EAGAIN;
		payload[0] = 0x49U;
		memcpy(payload + 1, runtime->iperf_event_uuid, RT_COMMAND_UUID_BYTES);
		payload[RT_COMMAND_UUID_BYTES + 1U] = runtime->iperf_event_status;
		airtime = radio_airtime_us(&runtime->config.radio_profile,
			NETWORK_FRAME_OVERHEAD + sizeof(payload));
		if (!network_node_tx_window(&runtime->node, runtime->frame_number, now, airtime))
			return -EAGAIN;
		{
			int error = send_payload(runtime, NETWORK_FRAME_STATUS, runtime->node.node_id,
				NETWORK_CONTROLLER_ID, payload, sizeof(payload), runtime->node_key);
			if (!error) {
				runtime->iperf_event_sent_frame = runtime->frame_number;
				if (runtime->command_agent &&
				    rt_command_agent_iperf_active(runtime->command_agent))
					runtime->iperf_grant_used_frame = runtime->frame_number;
			}
			return error;
		}
	}
	if (runtime->gap_pending && !runtime->tx_block.active &&
	    (runtime->gap_before_queue || (!runtime->capture_length &&
	    !network_queue_demand_bytes(&runtime->queue, NETWORK_CONTROLLER_ID)))) {
		uint8_t payload[14];
		int error;
		if (runtime->gap_sent_frame == runtime->frame_number)
			return -EAGAIN;
		payload[0] = 1U;
		put_u32(payload + 1, runtime->gap_stream_id);
		put_u32(payload + 5, runtime->gap_from);
		put_u32(payload + 9, runtime->gap_to);
		payload[13] = runtime->gap_reason;
		airtime = radio_airtime_us(&runtime->config.radio_profile,
			NETWORK_FRAME_OVERHEAD + sizeof(payload));
		if (!network_node_tx_window(&runtime->node, runtime->frame_number, now, airtime))
			return -EAGAIN;
		error = send_payload(runtime, NETWORK_FRAME_STATUS, runtime->node.node_id,
			NETWORK_CONTROLLER_ID, payload, sizeof(payload), runtime->node_key);
		if (!error) {
			runtime->gap_sent_frame = runtime->frame_number;
			runtime->gap_in_flight = true;
			if (runtime->command_agent &&
			    rt_command_agent_iperf_active(runtime->command_agent))
				runtime->iperf_grant_used_frame = runtime->frame_number;
		}
		return error;
	}
	if (!runtime->tx_block.active || !runtime->tx_block.via_rf)
		return -EAGAIN;
	if (runtime->sent_frame_number != runtime->frame_number) {
		runtime->sent_frame_number = runtime->frame_number;
		runtime->sent_frame_bitmap = 0;
	}
	for (i = 0; i < runtime->tx_block.count; i++) {
		uint8_t wire[NETWORK_FRAME_MAX_PAYLOAD];
		size_t length;
		int error;
		if ((runtime->tx_block.acknowledged & (1U << i)) ||
		    (runtime->sent_frame_bitmap & (1U << i)))
			continue;
		if (!network_retry_allowed(runtime->tx_block.attempts[i])) {
			runtime->last_error = -ETIMEDOUT;
			continue;
		}
		error = network_fragment_pack(&runtime->tx_block.fragments[i],
			wire, sizeof(wire), &length);
		if (error)
			return error;
		airtime = radio_airtime_us(&runtime->config.radio_profile,
			NETWORK_FRAME_OVERHEAD + length);
		if (runtime->command_agent && rt_command_agent_iperf_active(runtime->command_agent)) {
			if (runtime->iperf_grant_used_frame == runtime->frame_number ||
			    airtime > NETWORK_FRAME_MS * 100U)
				return -EAGAIN;
		}
		if (!network_node_tx_window(&runtime->node, runtime->frame_number, now, airtime))
			return -EAGAIN;
		error = send_payload(runtime, NETWORK_FRAME_DATA, runtime->node.node_id,
			NETWORK_CONTROLLER_ID, wire, length, runtime->node_key);
		if (!error) {
			runtime->tx_block.attempts[i]++;
			runtime->sent_frame_bitmap |= 1U << i;
			if (runtime->command_agent &&
			    rt_command_agent_iperf_active(runtime->command_agent))
				runtime->iperf_grant_used_frame = runtime->frame_number;
		}
		memset(wire, 0, sizeof(wire));
		return error;
	}
	return -EAGAIN;
}

static void grant_timer_cb(struct uloop_timeout *timer)
{
	struct rt_network_runtime *runtime = container_of(timer,
		struct rt_network_runtime, grant_timer);
	uint64_t now = runtime_now(runtime);
	runtime_timer_clear(runtime, RT_TIMER_GRANT);
	while (runtime->next_grant < runtime->node.grant_count) {
		const struct network_grant *grant = &runtime->node.grants[runtime->next_grant];
		uint64_t start, end;
		int error;
		if (grant->node_id != runtime->node.node_id) {
			runtime->next_grant++;
			continue;
		}
		start = runtime->node.frame_start_us + grant->start_offset_us;
		end = start + grant->airtime_budget_us;
		if (now < start) {
			(void)runtime_timer_set(runtime, RT_TIMER_GRANT,
				(unsigned int)((start - now + 999U) / 1000U));
			return;
		}
		if (now >= end) {
			runtime->next_grant++;
			continue;
		}
		if (runtime->command_agent && rt_command_agent_iperf_active(runtime->command_agent)) {
			size_t first = 0;
			while (first < runtime->node.grant_count &&
			    runtime->node.grants[first].node_id != runtime->node.node_id)
				first++;
			/* One LoRa packet in the first matching grant, capped at 10% of a frame. */
			if (runtime->iperf_grant_used_frame == runtime->frame_number ||
			    runtime->next_grant != first) {
				runtime->next_grant++;
				continue;
			}
		}
		error = send_node_grant_packet(runtime, grant);
		if (!error)
			return;
		if (error != -EAGAIN)
			runtime->last_error = error;
		runtime->next_grant++;
	}
}

static void contention_timer_cb(struct uloop_timeout *timer)
{
	struct rt_network_runtime *runtime = container_of(timer,
		struct rt_network_runtime, contention_timer);
	uint64_t now = runtime_now(runtime);
	runtime_timer_clear(runtime, RT_TIMER_CONTENTION);
	uint64_t end = runtime->contention_frame_start_us + NETWORK_FRAME_MS * 1000ULL;
	if (runtime->config.role != RT_NETWORK_NODE || !runtime->config.transmit_enabled ||
	    runtime->cad_active || runtime->tx_active || now < runtime->contention_start_us || now >= end)
		return;
	if (runtime->config.phy_ops && runtime->config.phy_ops->start_cad ?
	    runtime->config.phy_ops->start_cad(runtime->config.io_context) :
	    radio_linux_start_cad(runtime->config.radio)) {
		runtime->last_error = -EIO;
		(void)start_rx(runtime);
		schedule_contention_retry(runtime, now);
		return;
	}
	runtime->cad_active = true;
}

static void sync_timer_cb(struct uloop_timeout *timer)
{
	struct rt_network_runtime *runtime = container_of(timer,
		struct rt_network_runtime, sync_timer);
	uint32_t missed_frame;
	runtime_timer_clear(runtime, RT_TIMER_SYNC);
	if (runtime->config.role != RT_NETWORK_NODE || !runtime->node.joined)
		return;
	missed_frame = runtime->node.synced_frame + NETWORK_SYNC_LOSS_FRAMES;
	if (network_node_check_sync(&runtime->node, missed_frame))
		return;
	(void)network_node_begin_join(&runtime->node);
	runtime->node_id = NETWORK_UNASSIGNED_NODE_ID;
	runtime->joined = false;
	runtime->frame_number = missed_frame;
	runtime->contention_frame = missed_frame;
	runtime->contention_frame_start_us = 0;
	runtime->contention_start_us = 0;
	runtime->contention_attempt = 0;
	uloop_timeout_cancel(&runtime->contention_timer);
	runtime_timer_clear(runtime, RT_TIMER_CONTENTION);
	network_replay_begin_join(&runtime->replay);
}

static void flush_timer_cb(struct uloop_timeout *timer)
{
	struct rt_network_runtime *runtime = container_of(timer,
		struct rt_network_runtime, flush_timer);
	uint64_t now = runtime_now(runtime);
	runtime_timer_clear(runtime, RT_TIMER_FLUSH);
	if (runtime->config.role == RT_NETWORK_NODE) {
		if (runtime->capture_length && (runtime->capture_length >= RT_NETWORK_CAPTURE_BYTES ||
		    now - runtime->last_serial_flush_us >= RT_NETWORK_FLUSH_MS * 1000ULL))
			(void)flush_node_capture(runtime);
		(void)build_node_block(runtime);
		try_ip_block(runtime);
	} else if (runtime->config.role == RT_NETWORK_CONTROLLER) {
		flush_host_queue(runtime);
	}
	(void)runtime_timer_set(runtime, RT_TIMER_FLUSH, RT_NETWORK_FLUSH_MS);
}

static void serial_cb(struct uloop_fd *watcher, unsigned int events)
{
	struct rt_network_runtime *runtime = container_of(watcher,
		struct rt_network_runtime, serial_fd);
	uint8_t bytes[512];
	(void)events;
	for (;;) {
		ssize_t count = read(runtime->serial_fd_number, bytes, sizeof(bytes));
		if (count < 0 && errno == EINTR)
			continue;
		if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
			break;
		if (count <= 0) {
			runtime->last_error = count == 0 ? -EIO : -errno;
			runtime->serial_eof = true;
			uloop_fd_delete(&runtime->serial_fd);
			break;
		}
		append_serial_bytes(runtime, bytes, (size_t)count);
	}
	memset(bytes, 0, sizeof(bytes));
}

static int get_irq_packet(struct rt_network_runtime *runtime, uint8_t packet[NETWORK_FRAME_MAX_BYTES],
	size_t *length)
{
	if (runtime->config.phy_ops && runtime->config.phy_ops->get_rx)
		return runtime->config.phy_ops->get_rx(runtime->config.io_context, packet,
			NETWORK_FRAME_MAX_BYTES, length);
	if (!runtime->config.radio || !runtime->config.radio->last_rx_len ||
	    runtime->config.radio->last_rx_len > NETWORK_FRAME_MAX_BYTES)
		return -ENODATA;
	*length = runtime->config.radio->last_rx_len;
	memcpy(packet, runtime->config.radio->last_rx, *length);
	return 0;
}

static int on_receive_irq(struct rt_network_runtime *runtime, uint64_t irq_us)
{
	uint8_t packet[NETWORK_FRAME_MAX_BYTES];
	size_t packet_length = 0;
	struct network_frame peeked, decoded;
	struct rt_registry_entry *peer = NULL;
	int error;
	error = get_irq_packet(runtime, packet, &packet_length);
	if (error)
		return error;
	error = network_frame_peek(packet, packet_length, &peeked);
	if (error)
		return error;
	if (runtime->config.role == RT_NETWORK_CONTROLLER && peeked.type == NETWORK_FRAME_JOIN)
		return handle_join(runtime, packet, packet_length, &peeked);
	if (runtime->config.role == RT_NETWORK_NODE && peeked.type == NETWORK_FRAME_BEACON) {
		struct network_replay_table candidate;
		struct network_replay_table *beacon_replay;
		bool new_controller;
		if (peeked.source != NETWORK_CONTROLLER_ID ||
		    (peeked.destination != NETWORK_BROADCAST_ID &&
		     peeked.destination != runtime->node.node_id) || !peeked.controller_boot_nonce)
			return -EACCES;
		new_controller = !runtime->beacon_replay_ready ||
			runtime->beacon_replay.controller_boot_nonce != peeked.controller_boot_nonce;
		if (new_controller) {
			error = network_replay_init_successor(&candidate,
				runtime->beacon_replay_ready ? &runtime->beacon_replay : NULL,
				runtime->node.joined ? runtime->node.node_id : NETWORK_UNASSIGNED_NODE_ID,
				runtime->config.network_id, runtime->boot_nonce,
				peeked.controller_boot_nonce);
			if (error)
				return error;
			beacon_replay = &candidate;
		} else {
			beacon_replay = &runtime->beacon_replay;
		}
		error = network_frame_decode(packet, packet_length, runtime->beacon_key,
			beacon_replay, &decoded);
		if (error) {
			memset(packet, 0, sizeof(packet));
			return error;
		}
		/* Only the provisioned beacon key can replace the current join session. */
		if (new_controller) {
			if (runtime->node.joined) {
				(void)network_node_check_sync(&runtime->node, runtime->node.synced_frame + 1U);
				uloop_timeout_cancel(&runtime->sync_timer);
				runtime_timer_clear(runtime, RT_TIMER_SYNC);
				(void)network_node_begin_join(&runtime->node);
				runtime->node_id = NETWORK_UNASSIGNED_NODE_ID;
				runtime->joined = false;
				network_replay_begin_join(&runtime->replay);
			}
			memset(runtime->last_beacon_command_sequence, 0,
				sizeof(runtime->last_beacon_command_sequence));
			memset(runtime->beacon_command_seen, 0,
				sizeof(runtime->beacon_command_seen));
			runtime->beacon_replay = candidate;
			runtime->beacon_replay_ready = true;
		}
		process_frame(runtime, &decoded, NULL, irq_us);
		memset(packet, 0, sizeof(packet));
		return 0;
	}
	error = decode_for_runtime(runtime, packet, packet_length, &peeked, &decoded, &peer);
	if (error == -EINPROGRESS && runtime->config.role == RT_NETWORK_CONTROLLER)
		error = handle_join(runtime, packet, packet_length, &peeked);
	else if (!error)
		process_frame(runtime, &decoded, peer, irq_us);
	memset(packet, 0, sizeof(packet));
	return error;
}

int rt_network_runtime_on_irq(struct rt_network_runtime *runtime, uint16_t irq,
	uint64_t irq_monotonic_us)
{
	int error = 0;
	if (!runtime || !runtime->initialized)
		return -EINVAL;
	runtime->last_irq_us = irq_monotonic_us;
	if (irq & SX126X_IRQ_TX_DONE) {
		uint8_t completed_type = runtime->tx_type;
		uint8_t completed_destination = runtime->tx_destination;
		uint8_t completed_ack_kind = runtime->tx_ack_kind;
		runtime->tx_active = false;
		error = start_rx(runtime);
		if (error)
			return error;
		if (runtime->config.role == RT_NETWORK_CONTROLLER &&
		    completed_type == NETWORK_FRAME_BEACON) {
			runtime->frame_start_us = irq_monotonic_us;
			runtime->downlink_deadline_us = irq_monotonic_us +
				(uint64_t)NETWORK_DEFAULT_DOWNLINK_MS * 1000U;
			(void)runtime_timer_set(runtime, RT_TIMER_FRAME, NETWORK_FRAME_MS);
			(void)send_controller_downlink(runtime);
		} else if (runtime->config.role == RT_NETWORK_CONTROLLER &&
			(completed_type == NETWORK_FRAME_COMMAND || completed_type == NETWORK_FRAME_ACK) &&
			irq_monotonic_us < runtime->downlink_deadline_us) {
			if (completed_type == NETWORK_FRAME_ACK) {
				if (completed_ack_kind && completed_destination >= NETWORK_FIRST_NODE_ID &&
				    completed_destination <= NETWORK_MAX_ID)
					runtime->gap_ack_pending[completed_destination - 1U] = false;
				else if (completed_destination >= NETWORK_FIRST_NODE_ID &&
					completed_destination <= NETWORK_MAX_ID)
					runtime->command_ack_pending[completed_destination - 1U] = false;
			}
			(void)send_controller_downlink(runtime);
		} else if (runtime->config.role == RT_NETWORK_NODE && runtime->node.joined) {
			(void)runtime_timer_set(runtime, RT_TIMER_GRANT, 0);
		}
	}
	if (irq & SX126X_IRQ_TIMEOUT) {
		if (runtime->tx_active) {
			runtime->tx_active = false;
			runtime->last_error = -ETIMEDOUT;
			(void)start_rx(runtime);
		}
	}
	if ((irq & SX126X_IRQ_CAD_DONE) && runtime->cad_active) {
		bool busy = (irq & SX126X_IRQ_CAD_DETECTED) != 0;
		runtime->cad_active = false;
		if (runtime->config.phy_ops && runtime->config.phy_ops->cad_result) {
			error = runtime->config.phy_ops->cad_result(runtime->config.io_context, &busy);
		} else if (runtime->config.radio) {
			error = radio_linux_cad_result(runtime->config.radio, &busy);
		}
		if (error) {
			runtime->last_error = error;
			(void)start_rx(runtime);
			schedule_contention_retry(runtime, irq_monotonic_us);
		} else {
			bool in_window = irq_monotonic_us >= runtime->contention_start_us &&
				irq_monotonic_us < runtime->contention_frame_start_us +
					NETWORK_FRAME_MS * 1000ULL;
			if (network_contention_tx_allowed(in_window, !busy, true)) {
				error = send_contention_frame(runtime);
				if (error) {
					runtime->last_error = error;
					(void)start_rx(runtime);
					schedule_contention_retry(runtime, irq_monotonic_us);
				}
			} else {
				(void)start_rx(runtime);
				schedule_contention_retry(runtime, irq_monotonic_us);
			}
		}
	}
	if (irq & SX126X_IRQ_RX_DONE) {
		if (irq & (SX126X_IRQ_CRC_ERROR | SX126X_IRQ_HEADER_ERROR)) {
			runtime->last_error = -EBADMSG;
		} else {
			error = on_receive_irq(runtime, irq_monotonic_us);
			if (error && error != -EALREADY && error != -EACCES && error != -ENOENT &&
			    error != -ESTALE && error != -EINPROGRESS)
				runtime->last_error = error;
		}
		if (!runtime->tx_active)
			(void)start_rx(runtime);
	}
	return 0;
}

int rt_network_runtime_tick(struct rt_network_runtime *runtime)
{
	unsigned int iterations = 0;
	if (!runtime || !runtime->initialized)
		return -EINVAL;
	while (iterations++ < 64U) {
		uint64_t now = runtime_now(runtime), earliest = UINT64_MAX;
		void (*callback)(struct uloop_timeout *) = NULL;
		struct uloop_timeout *timer = NULL;
#define RT_DUE(field, cb, timer_field) \
		do { if (runtime->field && runtime->field <= now && runtime->field < earliest) { \
			earliest = runtime->field; callback = cb; timer = &runtime->timer_field; } } while (0)
		RT_DUE(frame_due_us, frame_timer_cb, frame_timer);
		RT_DUE(flush_due_us, flush_timer_cb, flush_timer);
		RT_DUE(grant_due_us, grant_timer_cb, grant_timer);
		RT_DUE(contention_due_us, contention_timer_cb, contention_timer);
		RT_DUE(sync_due_us, sync_timer_cb, sync_timer);
#undef RT_DUE
		if (!callback)
			return 0;
		callback(timer);
	}
	return -ELOOP;
}

void rt_network_runtime_add_status(const struct rt_network_runtime *runtime,
	struct blob_buf *buffer)
{
	if (!runtime || !buffer)
		return;
	blobmsg_add_string(buffer, "network_role",
		runtime->config.role == RT_NETWORK_CONTROLLER ? "controller" : "node");
	blobmsg_add_u32(buffer, "network_id", runtime->config.network_id);
	blobmsg_add_u32(buffer, "network_max_frame_airtime_us",
		radio_airtime_us(&runtime->config.radio_profile, NETWORK_FRAME_MAX_BYTES));
	blobmsg_add_u64(buffer, "network_boot_nonce", runtime->boot_nonce);
	blobmsg_add_u64(buffer, "network_controller_boot_nonce",
		runtime->config.role == RT_NETWORK_CONTROLLER ? runtime->boot_nonce :
		runtime->node.controller_boot_nonce);
	blobmsg_add_u32(buffer, "network_tx_sequence", runtime->tx_sequence);
	blobmsg_add_u8(buffer, "network_tx_enabled", runtime->config.transmit_enabled);
	blobmsg_add_u8(buffer, "network_joined", runtime->node.joined);
	blobmsg_add_u32(buffer, "network_node_id", runtime->node_id);
	blobmsg_add_u32(buffer, "network_frame", runtime->frame_number);
	blobmsg_add_u64(buffer, "network_beacon_replay_controller_nonce",
		runtime->beacon_replay.controller_boot_nonce);
	blobmsg_add_u64(buffer, "network_contention_start_us", runtime->contention_start_us);
	blobmsg_add_u64(buffer, "network_contention_due_us", runtime->contention_due_us);
	blobmsg_add_u32(buffer, "network_requested_airtime_us",
		runtime->config.role == RT_NETWORK_NODE ?
		node_requested_airtime(runtime) : 0);
	blobmsg_add_u32(buffer, "network_queue_bytes", (uint32_t)runtime->queue.used);
	blobmsg_add_u32(buffer, "network_serial_buffered", (uint32_t)runtime->capture_length);
	blobmsg_add_u8(buffer, "network_gap_pending", runtime->gap_pending);
	blobmsg_add_u8(buffer, "network_gap_in_flight", runtime->gap_in_flight);
	blobmsg_add_u8(buffer, "network_gap_before_queue", runtime->gap_before_queue);
	blobmsg_add_u32(buffer, "network_gap_reason", runtime->gap_reason);
	blobmsg_add_u32(buffer, "network_gap_from", runtime->gap_from);
	blobmsg_add_u32(buffer, "network_gap_to", runtime->gap_to);
	blobmsg_add_u8(buffer, "network_next_gap_pending", runtime->next_gap_pending);
	blobmsg_add_u32(buffer, "network_next_gap_from", runtime->next_gap_from);
	blobmsg_add_u32(buffer, "network_next_gap_to", runtime->next_gap_to);
	blobmsg_add_u32(buffer, "network_raw_offset", runtime->raw_offset);
	blobmsg_add_u8(buffer, "network_tx_block_active", runtime->tx_block.active);
	blobmsg_add_u32(buffer, "network_tx_ack_bitmap", runtime->tx_block.acknowledged);
	blobmsg_add_u8(buffer, "network_ip_healthy", runtime->ip_healthy);
	blobmsg_add_u8(buffer, "network_serial_eof", runtime->serial_eof);
	blobmsg_add_u32(buffer, "network_last_error",
		runtime->last_error ? (uint32_t)-runtime->last_error : 0);
}

int rt_network_runtime_capture(struct rt_network_runtime *runtime,
	const uint8_t *bytes, size_t length)
{
	if (!runtime || !runtime->initialized || runtime->config.role != RT_NETWORK_NODE ||
	    !bytes || !length)
		return -EINVAL;
	append_serial_bytes(runtime, bytes, length);
	return runtime->last_error == -EOVERFLOW ? -EOVERFLOW : 0;
}

int rt_network_runtime_test_exhaust_fragment(struct rt_network_runtime *runtime,
	uint8_t fragment_index, bool with_later_overflow_gap)
{
	int error;
	if (!runtime || !runtime->config.phy_ops || runtime->config.role != RT_NETWORK_NODE ||
	    !runtime->tx_block.active || fragment_index >= runtime->tx_block.count)
		return -EINVAL;
	if (with_later_overflow_gap && !runtime->gap_pending) {
		error = begin_queue_gap(runtime, 1U);
		if (error)
			return error;
	}
	runtime->tx_block.attempts[fragment_index] = NETWORK_MAX_RETRIES;
	error = retire_retry_exhausted_block(runtime);
	return error;
}

int rt_network_runtime_test_mark_gap_sent(struct rt_network_runtime *runtime)
{
	if (!runtime || !runtime->config.phy_ops || !runtime->gap_pending ||
	    runtime->gap_in_flight)
		return -EINVAL;
	runtime->gap_in_flight = true;
	return 0;
}

int rt_network_runtime_test_ack_gap(struct rt_network_runtime *runtime)
{
	struct network_frame frame = { 0 };
	if (!runtime || !runtime->config.phy_ops || !runtime->gap_pending ||
	    !runtime->gap_in_flight || runtime->config.role != RT_NETWORK_NODE)
		return -EINVAL;
	frame.type = NETWORK_FRAME_ACK;
	frame.source = NETWORK_CONTROLLER_ID;
	frame.destination = runtime->node.node_id;
	frame.payload[0] = 1U;
	put_u32(frame.payload + 1, runtime->gap_stream_id);
	put_u32(frame.payload + 5, runtime->gap_to);
	frame.payload_length = 9U;
	process_command_ack(runtime, &frame);
	return 0;
}

int rt_network_runtime_test_delivery_offset(const struct rt_network_runtime *runtime,
	uint8_t node_id, uint32_t stream_id, uint32_t *next_offset)
{
	const struct rt_delivery_cursor *cursor;
	if (!runtime || !runtime->config.phy_ops ||
	    runtime->config.role != RT_NETWORK_CONTROLLER || !next_offset ||
	    node_id < NETWORK_FIRST_NODE_ID || node_id > NETWORK_MAX_ID)
		return -EINVAL;
	cursor = &runtime->delivery[node_id - NETWORK_FIRST_NODE_ID];
	if (!cursor->initialized || cursor->stream_id != stream_id)
		return -ENOENT;
	*next_offset = cursor->next_offset;
	return 0;
}

uint32_t rt_network_runtime_test_airtime_us(const struct radio_config *profile,
	size_t packet_length)
{
	return radio_airtime_us(profile, packet_length);
}

int rt_network_runtime_test_set_peer_demand(struct rt_network_runtime *runtime,
	uint8_t node_id, uint64_t node_boot_nonce, uint32_t requested_airtime_us)
{
	struct rt_registry_entry *entry;
	if (!runtime || !runtime->config.phy_ops ||
	    runtime->config.role != RT_NETWORK_CONTROLLER || !node_boot_nonce ||
	    !requested_airtime_us || node_id < NETWORK_FIRST_NODE_ID || node_id > NETWORK_MAX_ID)
		return -EINVAL;
	entry = registry_by_id(runtime, node_id);
	if (!entry)
		return -ENOENT;
	entry->joined = true;
	entry->boot_nonce = node_boot_nonce;
	entry->requested_airtime_us = requested_airtime_us;
	entry->demand_expiry_frame = runtime->frame_number + RT_NETWORK_DEMAND_LEASE_FRAMES;
	return 0;
}

int rt_network_runtime_test_set_frame_number(struct rt_network_runtime *runtime,
	uint32_t frame_number)
{
	if (!runtime || !runtime->config.phy_ops ||
	    runtime->config.role != RT_NETWORK_CONTROLLER)
		return -EINVAL;
	runtime->frame_number = frame_number;
	return 0;
}

int rt_network_runtime_test_record_iperf_start(struct rt_network_runtime *runtime,
	const struct rt_command *command, const struct rt_command_result *result)
{
	if (!runtime || !runtime->config.phy_ops ||
	    runtime->config.role != RT_NETWORK_NODE || !command || !result)
		return -EINVAL;
	record_iperf_start_result(runtime, command, result);
	return 0;
}

int rt_network_runtime_test_iperf_complete(struct rt_network_runtime *runtime,
	const uint8_t request_uuid[RT_COMMAND_UUID_BYTES], int exit_status)
{
	if (!runtime || !runtime->config.phy_ops ||
	    runtime->config.role != RT_NETWORK_NODE || !request_uuid)
		return -EINVAL;
	iperf_event(runtime, request_uuid, exit_status);
	return 0;
}

int rt_network_runtime_test_iperf_state(const struct rt_network_runtime *runtime,
	uint8_t active_uuid[RT_COMMAND_UUID_BYTES],
	uint8_t event_uuid[RT_COMMAND_UUID_BYTES], bool *event_pending)
{
	if (!runtime || !runtime->config.phy_ops ||
	    runtime->config.role != RT_NETWORK_NODE || !active_uuid || !event_uuid ||
	    !event_pending)
		return -EINVAL;
	memcpy(active_uuid, runtime->active_iperf_test, RT_COMMAND_UUID_BYTES);
	memcpy(event_uuid, runtime->iperf_event_uuid, RT_COMMAND_UUID_BYTES);
	*event_pending = runtime->iperf_event_pending;
	return 0;
}

static int load_test_registry(struct rt_network_runtime *runtime)
{
	size_t i, j;
	if (!runtime->config.phy_ops || runtime->config.test_registry_count > RT_NETWORK_MAX_NODES ||
	    (runtime->config.test_registry_count && !runtime->config.test_registry))
		return -EINVAL;
	for (i = 0; i < runtime->config.test_registry_count; i++) {
		struct rt_registry_entry *entry = &runtime->registry[i];
		uint8_t any = 0, all_ff = 0xff;
		memcpy(entry->eui, runtime->config.test_registry[i].eui, sizeof(entry->eui));
		memcpy(entry->key, runtime->config.test_registry[i].psk, sizeof(entry->key));
		for (j = 0; j < sizeof(entry->eui); j++) {
			any |= entry->eui[j];
			all_ff &= entry->eui[j];
		}
		if (!any || all_ff == 0xff)
			return -EINVAL;
		for (j = 0; j < i; j++)
			if (!memcmp(runtime->registry[j].eui, entry->eui, sizeof(entry->eui)))
				return -EEXIST;
		entry->node_id = (uint8_t)(i + NETWORK_FIRST_NODE_ID);
	}
	runtime->registry_count = (uint8_t)runtime->config.test_registry_count;
	return 0;
}

int rt_network_runtime_start(struct rt_network_runtime **output,
	const struct rt_network_config *config)
{
	struct rt_network_runtime *runtime;
	int error;
	if (!output || !config)
		return -EINVAL;
	*output = NULL;
	if (config->role != RT_NETWORK_CONTROLLER && config->role != RT_NETWORK_NODE)
		return -EINVAL;
	if (!config->network_id ||
	    (!config->phy_ops && !config->radio) ||
	    (config->phy_ops && (!config->phy_ops->start_receive ||
		!config->phy_ops->start_transmit || !config->phy_ops->start_cad)) ||
	    radio_config_validate(&config->radio_profile))
		return -EINVAL;
	error = validate_network_airtime(&config->radio_profile);
	if (error)
		return error;
	if (config->transmit_enabled && config->radio && !config->phy_ops &&
	    !config->radio->network_tx_allowed)
		return -EACCES;
	runtime = calloc(1, sizeof(*runtime));
	if (!runtime)
		return -ENOMEM;
	runtime->config = *config;
	runtime->serial_fd_number = -1;
	runtime->serial_fd.fd = -1;
	runtime->frame_timer.cb = frame_timer_cb;
	runtime->flush_timer.cb = flush_timer_cb;
	runtime->grant_timer.cb = grant_timer_cb;
	runtime->contention_timer.cb = contention_timer_cb;
	runtime->sync_timer.cb = sync_timer_cb;
	runtime->beacon_command_request_index = -1;
	runtime->queue_storage = calloc(1, config->queue_bytes ? config->queue_bytes :
		NETWORK_QUEUE_MAX_BYTES);
	if (!runtime->queue_storage) {
		error = -ENOMEM;
		goto fail;
	}
	runtime->queue_storage_length = config->queue_bytes ? config->queue_bytes :
		NETWORK_QUEUE_MAX_BYTES;
	if ((config->queue_bytes ? config->queue_bytes : NETWORK_QUEUE_MAX_BYTES) >
	    NETWORK_QUEUE_MAX_BYTES ||
	    network_queue_init(&runtime->queue, runtime->queue_storage,
		config->queue_bytes ? config->queue_bytes : NETWORK_QUEUE_MAX_BYTES)) {
		error = -EINVAL;
		goto fail;
	}
	if (config->phy_ops && config->test_boot_nonce) {
		runtime->boot_nonce = config->test_boot_nonce;
	} else {
		error = random_u64(&runtime->boot_nonce);
		if (error)
			goto fail;
	}
	runtime->stream_id = (uint32_t)runtime->boot_nonce;
	if (!runtime->stream_id)
		runtime->stream_id = 1;
	runtime->last_serial_flush_us = runtime_now(runtime);
	network_reassembler_init(&runtime->reassembler);
	if (config->test_beacon_key && config->phy_ops)
		memcpy(runtime->beacon_key, config->test_beacon_key, sizeof(runtime->beacon_key));
	else {
		error = rt_host_key_load(config->beacon_key_path, runtime->beacon_key);
		if (error)
			goto fail;
	}
	if (config->role == RT_NETWORK_CONTROLLER) {
		if (config->test_registry) {
			error = load_test_registry(runtime);
		} else {
			error = load_registry(runtime);
		}
		if (error)
			goto fail;
		network_replay_init(&runtime->replay, NETWORK_CONTROLLER_ID,
			config->network_id, runtime->boot_nonce, runtime->boot_nonce);
		error = network_scheduler_init(&runtime->scheduler,
			config->airtime_budget_us ? config->airtime_budget_us : 3450000U,
			NETWORK_DEFAULT_DOWNLINK_MS);
		if (error)
			goto fail;
	} else {
		error = parse_hex(config->node_eui, 16, runtime->node_eui,
			sizeof(runtime->node_eui), true);
		if (error)
			goto fail;
		if (config->test_node_key && config->phy_ops)
			memcpy(runtime->node_key, config->test_node_key, sizeof(runtime->node_key));
		else {
			error = rt_host_key_load(config->node_psk_path, runtime->node_key);
			if (error)
				goto fail;
		}
		network_node_init(&runtime->node, config->network_id,
			runtime->boot_nonce, runtime->node_eui);
		error = network_node_begin_join(&runtime->node);
		if (error)
			goto fail;
		runtime->node_id = NETWORK_UNASSIGNED_NODE_ID;
		network_replay_init(&runtime->replay, NETWORK_UNASSIGNED_NODE_ID,
			config->network_id, runtime->boot_nonce, 0);
	}
	if (config->role == RT_NETWORK_NODE && runtime->serial_fd_number < 0 &&
	    config->serial_path && config->serial_path[0]) {
		runtime->serial_fd_number = open_serial(config->serial_path);
		if (runtime->serial_fd_number < 0) {
			error = runtime->serial_fd_number;
			runtime->serial_fd_number = -1;
			goto fail;
		}
	}
	if (config->role == RT_NETWORK_NODE && runtime->serial_fd_number >= 0) {
		runtime->serial_fd.fd = runtime->serial_fd_number;
		runtime->serial_fd.cb = serial_cb;
		if (uloop_fd_add(&runtime->serial_fd, ULOOP_READ)) {
			error = -EIO;
			goto fail;
		}
		runtime->command_agent = rt_command_agent_start(runtime->serial_fd_number,
			command_agent_iperf_event, runtime);
		if (!runtime->command_agent) {
			error = -ENOMEM;
			goto fail;
		}
	}
	if (config->role == RT_NETWORK_CONTROLLER && config->host_port &&
	    config->host_psk_path && config->host_psk_path[0]) {
		runtime->host = rt_host_server_start(config->host_port, config->host_uart_path,
			config->host_psk_path, host_request, runtime);
		if (!runtime->host) {
			error = errno ? -errno : -EIO;
			goto fail;
		}
	}
	if (config->role == RT_NETWORK_CONTROLLER && config->node_port) {
		runtime->ip_server = rt_ip_server_start(config->node_port,
			ip_lookup, ip_receive, runtime);
		if (!runtime->ip_server) {
			error = errno ? -errno : -EIO;
			goto fail;
		}
	}
	if (config->role == RT_NETWORK_NODE && config->controller_ipv4 &&
	    config->controller_ipv4[0] && config->node_port) {
		runtime->ip_client = rt_ip_client_start(config->controller_ipv4,
			config->node_port, runtime->node_eui, runtime->node_key,
			ip_acknowledge, ip_state_changed, runtime);
		if (!runtime->ip_client) {
			error = errno ? -errno : -EIO;
			goto fail;
		}
	} else if (config->role == RT_NETWORK_NODE && !config->phy_ops) {
		error = -EINVAL;
		goto fail;
	}
	error = start_rx(runtime);
	if (error)
		goto fail;
	runtime->initialized = true;
	if (config->role == RT_NETWORK_CONTROLLER)
		(void)runtime_timer_set(runtime, RT_TIMER_FRAME, 0);
	(void)runtime_timer_set(runtime, RT_TIMER_FLUSH, RT_NETWORK_FLUSH_MS);
	*output = runtime;
	return 0;
fail:
	rt_network_runtime_stop(runtime);
	return error;
}

void rt_network_runtime_stop(struct rt_network_runtime *runtime)
{
	if (!runtime)
		return;
	uloop_timeout_cancel(&runtime->frame_timer);
	uloop_timeout_cancel(&runtime->flush_timer);
	uloop_timeout_cancel(&runtime->grant_timer);
	uloop_timeout_cancel(&runtime->contention_timer);
	uloop_timeout_cancel(&runtime->sync_timer);
	if (runtime->serial_fd.fd >= 0) {
		uloop_fd_delete(&runtime->serial_fd);
		runtime->serial_fd.fd = -1;
	}
	if (runtime->ip_client) {
		rt_ip_client_stop(runtime->ip_client);
		runtime->ip_client = NULL;
	}
	if (runtime->command_agent) {
		rt_command_agent_stop(runtime->command_agent);
		runtime->command_agent = NULL;
	}
	if (runtime->ip_server)
		rt_ip_server_stop(runtime->ip_server);
	if (runtime->host)
		rt_host_server_stop(runtime->host);
	if (runtime->serial_fd_number >= 0)
		close(runtime->serial_fd_number);
	if (runtime->config.radio)
		(void)radio_linux_set_network_tx_allowed(runtime->config.radio, false);
	if (runtime->queue_storage) {
		memset(runtime->queue_storage, 0, runtime->queue_storage_length);
		free(runtime->queue_storage);
	}
	memset(runtime->beacon_key, 0, sizeof(runtime->beacon_key));
	memset(runtime->node_key, 0, sizeof(runtime->node_key));
	memset(runtime->registry, 0, sizeof(runtime->registry));
	memset(runtime, 0, sizeof(*runtime));
	free(runtime);
}
