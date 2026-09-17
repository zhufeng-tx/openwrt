/* SPDX-License-Identifier: GPL-2.0-only */
#include "radio_linux.h"
#include "vendor/sx126x/sx126x.h"
#include <errno.h>
#include <gpiod.h>
#include <libubox/blobmsg_json.h>
#include <libubox/uloop.h>
#include <libubus.h>
#include <stdbool.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <uci.h>

enum { SCAN_START, SCAN_END, SCAN_DWELL, __SCAN_MAX };
enum { RECEIVE_TIMEOUT, __RECEIVE_MAX };
enum { TX_ANTENNA_CONFIRMED, __TX_MAX };

static const struct blobmsg_policy scan_policy[__SCAN_MAX] = {
	[SCAN_START] = { .name = "start_mhz", .type = BLOBMSG_TYPE_INT32 },
	[SCAN_END] = { .name = "end_mhz", .type = BLOBMSG_TYPE_INT32 },
	[SCAN_DWELL] = { .name = "dwell_ms", .type = BLOBMSG_TYPE_INT32 },
};
static const struct blobmsg_policy receive_policy[__RECEIVE_MAX] = {
	[RECEIVE_TIMEOUT] = { .name = "timeout_ms", .type = BLOBMSG_TYPE_INT32 },
};
static const struct blobmsg_policy tx_policy[__TX_MAX] = {
	[TX_ANTENNA_CONFIRMED] = { .name = "antenna_confirmed", .type = BLOBMSG_TYPE_BOOL },
};

struct settings {
	struct radio_config profile;
	struct radio_lines lines;
	char spidev[64];
	char gpiochip[64];
	char reset[64];
	char busy[64];
	char dio1[64];
	char txen[64];
	char rxen[64];
	bool enabled;
};

struct daemon {
	struct ubus_context *ubus;
	struct ubus_object object;
	struct radio_linux radio;
	struct settings settings;
	struct uloop_timeout operation_timer;
	struct uloop_fd dio_fd;
	struct ubus_request_data deferred;
	enum radio_op operation;
	struct radio_scan_request scan;
	uint32_t scan_frequency;
	uint32_t scan_count;
	uint64_t scan_deadline_ms;
	int16_t scan_rssi[81];
	uint32_t receive_timeout_ms;
};

static const char *option_string(struct uci_context *uci, struct uci_section *section, const char *name, const char *fallback)
{
	const char *value = uci_lookup_option_string(uci, section, name);
	return value ? value : fallback;
}

static int parse_u32(const char *string, uint32_t *value)
{
	char *end;
	unsigned long parsed = strtoul(string, &end, 0);
	if (!string[0] || *end || parsed > UINT32_MAX)
		return -EINVAL;
	*value = parsed;
	return 0;
}

static int copy_option(char *target, size_t target_size, const char *value)
{
	if (strlen(value) >= target_size)
		return -ENAMETOOLONG;
	strcpy(target, value);
	return 0;
}

static int load_settings(struct settings *settings)
{
	struct uci_context *uci;
	struct uci_package *package = NULL;
	struct uci_section *section = NULL;
	struct uci_element *element;
	const char *value;
	int err = 0;

	memset(settings, 0, sizeof(*settings));
	settings->profile.frequency_mhz = RADIO_DEFAULT_MHZ;
	settings->profile.bandwidth_khz = 125;
	settings->profile.spreading_factor = 7;
	settings->profile.coding_rate = 5;
	settings->profile.sync_word = 0x1424;
	settings->profile.spi_hz = RADIO_DEFAULT_SPI_HZ;
	settings->enabled = true;
	uci = uci_alloc_context();
	if (!uci) return -ENOMEM;
	if (uci_load(uci, "remote-tester-radio", &package)) { err = -ENOENT; goto out; }
	uci_foreach_element(&package->sections, element) {
		struct uci_section *candidate = uci_to_section(element);
		if (!strcmp(candidate->type, "radio")) { section = candidate; break; }
	}
	if (!section) { err = -ENOENT; goto out; }
	value = option_string(uci, section, "enabled", "1");
	settings->enabled = !strcmp(value, "1");
	value = option_string(uci, section, "disabled", "0");
	if (!strcmp(value, "1")) settings->enabled = false;
	if (!settings->enabled) { err = -ECANCELED; goto out; }
	#define LOAD_STRING(member, option, fallback) do { value = option_string(uci, section, option, fallback); if (!err) err = copy_option(settings->member, sizeof(settings->member), value); } while (0)
	#define LOAD_U32(member, option, fallback) do { value = option_string(uci, section, option, fallback); if (!err) err = parse_u32(value, &settings->profile.member); } while (0)
	LOAD_STRING(spidev, "spidev", "/dev/spidev0.1");
	LOAD_STRING(gpiochip, "gpiochip", "/dev/gpiochip0");
	LOAD_STRING(reset, "reset_line", "LORA_RESET_N");
	LOAD_STRING(busy, "busy_line", "LORA_BUSY");
	LOAD_STRING(dio1, "dio1_line", "LORA_DIO1");
	LOAD_STRING(txen, "txen_line", "LORA_TXEN");
	LOAD_STRING(rxen, "rxen_line", "LORA_RXEN");
	LOAD_U32(frequency_mhz, "frequency_mhz", "433");
	LOAD_U32(bandwidth_khz, "bandwidth_khz", "125");
	LOAD_U32(spreading_factor, "spreading_factor", "7");
	LOAD_U32(coding_rate, "coding_rate", "5");
	LOAD_U32(sync_word, "sync_word", "0x1424");
	LOAD_U32(spi_hz, "spi_hz", "2000000");
	value = option_string(uci, section, "allow_tx_test", "0"); settings->profile.allow_tx_test = !strcmp(value, "1");
	#undef LOAD_STRING
	#undef LOAD_U32
	settings->lines.reset = settings->reset;
	settings->lines.busy = settings->busy;
	settings->lines.dio1 = settings->dio1;
	settings->lines.txen = settings->txen;
	settings->lines.rxen = settings->rxen;
	if (!err) err = radio_config_validate(&settings->profile);
out:
	if (package) uci_unload(uci, package);
	uci_free_context(uci);
	return err;
}

static bool operation_busy(const struct daemon *daemon)
{
	return !radio_op_can_start(daemon->operation);
}

static uint64_t monotonic_ms(void)
{
	struct timespec now;

	if (clock_gettime(CLOCK_MONOTONIC, &now)) return 0;
	return (uint64_t)now.tv_sec * 1000 + (uint64_t)now.tv_nsec / 1000000;
}

static int schedule_scan_dwell(struct daemon *daemon)
{
	uint64_t now = monotonic_ms();

	if (!radio_scan_dwell_fits(now, daemon->scan_deadline_ms, daemon->scan.dwell_ms))
		return -ETIMEDOUT;
	uloop_timeout_set(&daemon->operation_timer, daemon->scan.dwell_ms);
	return 0;
}

static bool scan_deadline_expired(const struct daemon *daemon)
{
	uint64_t now = monotonic_ms();

	return !now || now >= daemon->scan_deadline_ms;
}

static int reply_busy(struct daemon *daemon, struct ubus_request_data *request)
{
	struct blob_buf buffer = {};
	blob_buf_init(&buffer, 0);
	blobmsg_add_u8(&buffer, "busy", true);
	blobmsg_add_u32(&buffer, "operation", daemon->operation);
	ubus_send_reply(daemon->ubus, request, buffer.head);
	blob_buf_free(&buffer);
	/* ubus has no BUSY status code; the reply body carries the explicit state. */
	return UBUS_STATUS_UNKNOWN_ERROR;
}

static void add_status(struct daemon *daemon, struct blob_buf *buffer, int result)
{
	blobmsg_add_u8(buffer, "ready", daemon->radio.configured && !daemon->radio.faulted);
	blobmsg_add_u8(buffer, "faulted", daemon->radio.faulted);
	blobmsg_add_u32(buffer, "operation", daemon->operation);
	blobmsg_add_u32(buffer, "frequency_mhz", daemon->settings.profile.frequency_mhz);
	blobmsg_add_u32(buffer, "bandwidth_khz", daemon->settings.profile.bandwidth_khz);
	blobmsg_add_u32(buffer, "spreading_factor", daemon->settings.profile.spreading_factor);
	blobmsg_add_u32(buffer, "coding_rate", daemon->settings.profile.coding_rate);
	blobmsg_add_u32(buffer, "sync_word", daemon->settings.profile.sync_word);
	blobmsg_add_u32(buffer, "spi_hz", daemon->settings.profile.spi_hz);
	blobmsg_add_u8(buffer, "tx_test_enabled", daemon->settings.profile.allow_tx_test);
	blobmsg_add_u32(buffer, "last_irq", daemon->radio.last_irq);
	blobmsg_add_u32(buffer, "result", result ? (uint32_t)-result : 0);
}

static void complete_deferred(struct daemon *daemon, struct blob_buf *buffer, int result)
{
	ubus_send_reply(daemon->ubus, &daemon->deferred, buffer->head);
	ubus_complete_deferred_request(daemon->ubus, &daemon->deferred, result ? UBUS_STATUS_UNKNOWN_ERROR : UBUS_STATUS_OK);
}

static void finish_operation(struct daemon *daemon, int result)
{
	struct blob_buf buffer = {};
	int cleanup = radio_linux_cleanup(&daemon->radio);
	if (!result && cleanup) result = cleanup;
	uloop_timeout_cancel(&daemon->operation_timer);
	daemon->operation = RADIO_OP_IDLE;
	blob_buf_init(&buffer, 0);
	add_status(daemon, &buffer, result);
	complete_deferred(daemon, &buffer, result);
	blob_buf_free(&buffer);
}

static void finish_receive(struct daemon *daemon, bool received, int result)
{
	struct blob_buf buffer = {};
	char payload_hex[sizeof(daemon->radio.last_rx) * 2 + 1];
	uint32_t index;
	int cleanup = radio_linux_cleanup(&daemon->radio);
	if (!result && cleanup) result = cleanup;
	uloop_timeout_cancel(&daemon->operation_timer);
	daemon->operation = RADIO_OP_IDLE;
	blob_buf_init(&buffer, 0);
	add_status(daemon, &buffer, result);
	blobmsg_add_u8(&buffer, "received", received);
	blobmsg_add_u32(&buffer, "irq", daemon->radio.last_irq);
	if (received) {
		for (index = 0; index < daemon->radio.last_rx_len; index++)
			snprintf(&payload_hex[index * 2], 3, "%02x", daemon->radio.last_rx[index]);
		payload_hex[daemon->radio.last_rx_len * 2] = '\0';
		blobmsg_add_string(&buffer, "payload_hex", payload_hex);
		blobmsg_add_u32(&buffer, "payload_length", daemon->radio.last_rx_len);
		blobmsg_add_u32(&buffer, "rssi_dbm", (uint32_t)(int32_t)daemon->radio.last_rssi_dbm);
		blobmsg_add_u32(&buffer, "snr_db", (uint32_t)(int32_t)daemon->radio.last_snr_db);
	}
	complete_deferred(daemon, &buffer, result);
	blob_buf_free(&buffer);
}

static void finish_tx(struct daemon *daemon, bool tx_done, int result)
{
	struct blob_buf buffer = {};
	int cleanup = radio_linux_cleanup(&daemon->radio);
	if (!result && cleanup) result = cleanup;
	uloop_timeout_cancel(&daemon->operation_timer);
	daemon->operation = RADIO_OP_IDLE;
	blob_buf_init(&buffer, 0);
	add_status(daemon, &buffer, result);
	blobmsg_add_u8(&buffer, "tx_done", tx_done);
	blobmsg_add_u32(&buffer, "irq", daemon->radio.last_irq);
	complete_deferred(daemon, &buffer, result);
	blob_buf_free(&buffer);
}

static void finish_scan(struct daemon *daemon, int result)
{
	struct blob_buf buffer = {};
	void *array;
	uint32_t index;
	int cleanup;

	cleanup = radio_linux_cleanup(&daemon->radio);
	if (!result && cleanup) result = cleanup;
	if (!cleanup) {
		int restore = radio_linux_set_frequency(&daemon->radio, daemon->settings.profile.frequency_mhz);
		if (restore) {
			daemon->radio.faulted = true;
			if (!result) result = restore;
		}
	}
	if (!result && scan_deadline_expired(daemon)) result = -ETIMEDOUT;
	uloop_timeout_cancel(&daemon->operation_timer);
	daemon->operation = RADIO_OP_IDLE;
	blob_buf_init(&buffer, 0);
	add_status(daemon, &buffer, result);
	array = blobmsg_open_array(&buffer, "samples");
	for (index = 0; index < daemon->scan_count; index++) {
		void *sample = blobmsg_open_table(&buffer, NULL);
		blobmsg_add_u32(&buffer, "frequency_mhz", daemon->scan.start_mhz + index);
		blobmsg_add_u32(&buffer, "rssi_dbm", (uint32_t)(int32_t)daemon->scan_rssi[index]);
		blobmsg_close_table(&buffer, sample);
	}
	blobmsg_close_array(&buffer, array);
	complete_deferred(daemon, &buffer, result);
	blob_buf_free(&buffer);
}

static int start_deferred(struct daemon *daemon, struct ubus_request_data *request, enum radio_op operation)
{
	if (operation_busy(daemon)) return -EBUSY;
	if (daemon->radio.faulted) return -EIO;
	ubus_defer_request(daemon->ubus, request, &daemon->deferred);
	daemon->operation = operation;
	return 0;
}

static void scan_timer_cb(struct uloop_timeout *timer)
{
	struct daemon *daemon = container_of(timer, struct daemon, operation_timer);
	int16_t rssi;
	int err;

	if (scan_deadline_expired(daemon)) { finish_scan(daemon, -ETIMEDOUT); return; }
	err = radio_linux_sample_rssi(&daemon->radio, &rssi);
	if (err) { finish_scan(daemon, err); return; }
	if (scan_deadline_expired(daemon)) { finish_scan(daemon, -ETIMEDOUT); return; }
	daemon->scan_rssi[daemon->scan_count++] = rssi;
	if (daemon->scan_frequency == daemon->scan.end_mhz) { finish_scan(daemon, 0); return; }
	daemon->scan_frequency++;
	err = radio_linux_cleanup(&daemon->radio);
	if (!err && scan_deadline_expired(daemon)) err = -ETIMEDOUT;
	if (!err) err = radio_linux_set_frequency(&daemon->radio, daemon->scan_frequency);
	if (!err && scan_deadline_expired(daemon)) err = -ETIMEDOUT;
	if (!err) err = radio_linux_start_receive(&daemon->radio, 240, true);
	if (!err && scan_deadline_expired(daemon)) err = -ETIMEDOUT;
	if (err) { finish_scan(daemon, err); return; }
	err = schedule_scan_dwell(daemon);
	if (err) finish_scan(daemon, err);
}

static void receive_timer_cb(struct uloop_timeout *timer)
{
	struct daemon *daemon = container_of(timer, struct daemon, operation_timer);
	finish_receive(daemon, false, 0);
}

static void tx_timer_cb(struct uloop_timeout *timer)
{
	struct daemon *daemon = container_of(timer, struct daemon, operation_timer);
	finish_tx(daemon, false, -ETIMEDOUT);
}

static void dio_cb(struct uloop_fd *fd, unsigned int events)
{
	struct daemon *daemon = container_of(fd, struct daemon, dio_fd);
	struct gpiod_line_event event;
	uint16_t irq;
	int err;
	(void)events;
	if (gpiod_line_event_read(daemon->radio.dio1, &event)) return;
	err = radio_linux_handle_irq(&daemon->radio, &irq);
	if (err) {
		if (daemon->operation == RADIO_OP_RECEIVE) finish_receive(daemon, false, err);
		else if (daemon->operation == RADIO_OP_TX) finish_tx(daemon, false, err);
		return;
	}
	if (daemon->operation == RADIO_OP_RECEIVE &&
	    (irq & (SX126X_IRQ_RX_DONE | SX126X_IRQ_TIMEOUT | SX126X_IRQ_CRC_ERROR | SX126X_IRQ_HEADER_ERROR))) {
		bool packet_valid = (irq & SX126X_IRQ_RX_DONE) && !(irq & (SX126X_IRQ_CRC_ERROR | SX126X_IRQ_HEADER_ERROR));
		finish_receive(daemon, packet_valid,
			(irq & (SX126X_IRQ_CRC_ERROR | SX126X_IRQ_HEADER_ERROR)) ? -EBADMSG : 0);
	}
	if (daemon->operation == RADIO_OP_TX && (irq & (SX126X_IRQ_TX_DONE | SX126X_IRQ_TIMEOUT)))
		finish_tx(daemon, (irq & SX126X_IRQ_TX_DONE) != 0, (irq & SX126X_IRQ_TX_DONE) ? 0 : -ETIMEDOUT);
}

static int status_cb(struct ubus_context *context, struct ubus_object *object, struct ubus_request_data *request,
	const char *method, struct blob_attr *message)
{
	struct daemon *daemon = container_of(object, struct daemon, object);
	struct blob_buf buffer = {};
	(void)context; (void)method; (void)message;
	blob_buf_init(&buffer, 0);
	add_status(daemon, &buffer, 0);
	ubus_send_reply(daemon->ubus, request, buffer.head);
	blob_buf_free(&buffer);
	return UBUS_STATUS_OK;
}

static int probe_cb(struct ubus_context *context, struct ubus_object *object, struct ubus_request_data *request,
	const char *method, struct blob_attr *message)
{
	struct daemon *daemon = container_of(object, struct daemon, object);
	struct blob_buf buffer = {};
	int result;
	(void)context; (void)method; (void)message;
	if (operation_busy(daemon)) return reply_busy(daemon, request);
	result = radio_linux_probe(&daemon->radio, &daemon->settings.profile);
	blob_buf_init(&buffer, 0);
	add_status(daemon, &buffer, result);
	blobmsg_add_u32(&buffer, "expected_sync_word", daemon->settings.profile.sync_word);
	blobmsg_add_u32(&buffer, "observed_sync_word", daemon->radio.last_sync_word);
	blobmsg_add_u32(&buffer, "chip_mode", daemon->radio.last_chip_mode);
	blobmsg_add_u32(&buffer, "command_status", daemon->radio.last_command_status);
	ubus_send_reply(daemon->ubus, request, buffer.head);
	blob_buf_free(&buffer);
	return result ? UBUS_STATUS_UNKNOWN_ERROR : UBUS_STATUS_OK;
}

static int scan_cb(struct ubus_context *context, struct ubus_object *object, struct ubus_request_data *request,
	const char *method, struct blob_attr *message)
{
	struct daemon *daemon = container_of(object, struct daemon, object);
	struct blob_attr *attributes[__SCAN_MAX];
	struct radio_scan_request scan;
	int result;
	(void)context; (void)method;
	blobmsg_parse(scan_policy, __SCAN_MAX, attributes, blob_data(message), blob_len(message));
	if (!attributes[SCAN_START] || !attributes[SCAN_END] || !attributes[SCAN_DWELL]) return UBUS_STATUS_INVALID_ARGUMENT;
	scan.start_mhz = blobmsg_get_u32(attributes[SCAN_START]);
	scan.end_mhz = blobmsg_get_u32(attributes[SCAN_END]);
	scan.dwell_ms = blobmsg_get_u32(attributes[SCAN_DWELL]);
	if (radio_scan_validate(&scan)) return UBUS_STATUS_INVALID_ARGUMENT;
	if (operation_busy(daemon)) return reply_busy(daemon, request);
	result = start_deferred(daemon, request, RADIO_OP_SCAN);
	if (result) return UBUS_STATUS_UNKNOWN_ERROR;
	daemon->scan = scan;
	daemon->scan_frequency = daemon->scan.start_mhz;
	daemon->scan_count = 0;
	daemon->scan_deadline_ms = monotonic_ms() + 60000;
	result = radio_linux_set_frequency(&daemon->radio, daemon->scan_frequency);
	if (!result) result = radio_linux_start_receive(&daemon->radio, 240, true);
	if (result) { finish_scan(daemon, result); return UBUS_STATUS_OK; }
	daemon->operation_timer.cb = scan_timer_cb;
	result = schedule_scan_dwell(daemon);
	if (result) finish_scan(daemon, result);
	return UBUS_STATUS_OK;
}

static int receive_cb(struct ubus_context *context, struct ubus_object *object, struct ubus_request_data *request,
	const char *method, struct blob_attr *message)
{
	struct daemon *daemon = container_of(object, struct daemon, object);
	struct blob_attr *attributes[__RECEIVE_MAX];
	int result;
	(void)context; (void)method;
	blobmsg_parse(receive_policy, __RECEIVE_MAX, attributes, blob_data(message), blob_len(message));
	if (!attributes[RECEIVE_TIMEOUT]) return UBUS_STATUS_INVALID_ARGUMENT;
	daemon->receive_timeout_ms = blobmsg_get_u32(attributes[RECEIVE_TIMEOUT]);
	if (daemon->receive_timeout_ms < 100 || daemon->receive_timeout_ms > 60000) return UBUS_STATUS_INVALID_ARGUMENT;
	if (operation_busy(daemon)) return reply_busy(daemon, request);
	result = start_deferred(daemon, request, RADIO_OP_RECEIVE);
	if (result) return UBUS_STATUS_UNKNOWN_ERROR;
	result = radio_linux_start_receive(&daemon->radio, 240, false);
	if (result) { finish_receive(daemon, false, result); return UBUS_STATUS_OK; }
	daemon->operation_timer.cb = receive_timer_cb;
	uloop_timeout_set(&daemon->operation_timer, daemon->receive_timeout_ms);
	return UBUS_STATUS_OK;
}

static int tx_cb(struct ubus_context *context, struct ubus_object *object, struct ubus_request_data *request,
	const char *method, struct blob_attr *message)
{
	struct daemon *daemon = container_of(object, struct daemon, object);
	struct blob_attr *attributes[__TX_MAX];
	int result;
	(void)context; (void)method;
	blobmsg_parse(tx_policy, __TX_MAX, attributes, blob_data(message), blob_len(message));
	if (!attributes[TX_ANTENNA_CONFIRMED] ||
	    !radio_tx_allowed(&daemon->settings.profile, blobmsg_get_bool(attributes[TX_ANTENNA_CONFIRMED])))
		return UBUS_STATUS_PERMISSION_DENIED;
	if (operation_busy(daemon)) return reply_busy(daemon, request);
	result = start_deferred(daemon, request, RADIO_OP_TX);
	if (result) return UBUS_STATUS_UNKNOWN_ERROR;
	result = radio_linux_start_tx_test(&daemon->radio);
	if (result) { finish_tx(daemon, false, result); return UBUS_STATUS_OK; }
	daemon->operation_timer.cb = tx_timer_cb;
	uloop_timeout_set(&daemon->operation_timer, 2000);
	return UBUS_STATUS_OK;
}

static const struct ubus_method methods[] = {
	UBUS_METHOD_NOARG("status", status_cb),
	UBUS_METHOD_NOARG("probe", probe_cb),
	UBUS_METHOD("scan", scan_cb, scan_policy),
	UBUS_METHOD("receive", receive_cb, receive_policy),
	UBUS_METHOD("tx_test", tx_cb, tx_policy),
};
static struct ubus_object_type radio_type = UBUS_OBJECT_TYPE("remote_tester.radio", methods);

static volatile sig_atomic_t stop_requested;

static void terminate_cb(int signo)
{
	(void)signo;
	stop_requested = 1;
	uloop_end();
}

int main(void)
{
	struct daemon daemon = {};
	int result;

	result = load_settings(&daemon.settings);
	if (result) { fprintf(stderr, "radio UCI profile: %s\n", strerror(-result)); return 1; }
	result = radio_linux_open(&daemon.radio, daemon.settings.spidev, daemon.settings.gpiochip,
		&daemon.settings.lines, &daemon.settings.profile);
	if (result) { fprintf(stderr, "radio resources: %s\n", strerror(-result)); return 1; }
	/* A chip/configuration failure remains observable through ubus and is recoverable only by probe. */
	(void)radio_linux_configure(&daemon.radio, &daemon.settings.profile, 240);
	uloop_init();
	daemon.ubus = ubus_connect(NULL);
	if (!daemon.ubus) { (void)radio_linux_cleanup(&daemon.radio); radio_linux_close(&daemon.radio); return 1; }
	ubus_add_uloop(daemon.ubus);
	daemon.dio_fd.fd = gpiod_line_event_get_fd(daemon.radio.dio1);
	daemon.dio_fd.cb = dio_cb;
	uloop_fd_add(&daemon.dio_fd, ULOOP_READ);
	signal(SIGTERM, terminate_cb);
	signal(SIGINT, terminate_cb);
	daemon.object.name = "remote_tester.radio";
	daemon.object.type = &radio_type;
	daemon.object.methods = methods;
	daemon.object.n_methods = ARRAY_SIZE(methods);
	if (ubus_add_object(daemon.ubus, &daemon.object)) {
		ubus_free(daemon.ubus);
		(void)radio_linux_cleanup(&daemon.radio);
		uloop_done();
		radio_linux_close(&daemon.radio);
		return 1;
	}
	uloop_run();
	if (stop_requested && operation_busy(&daemon)) finish_operation(&daemon, -ECANCELED);
	(void)radio_linux_cleanup(&daemon.radio);
	ubus_free(daemon.ubus);
	uloop_done();
	radio_linux_close(&daemon.radio);
	return 0;
}
