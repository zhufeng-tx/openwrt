#define _GNU_SOURCE

#include <microhttpd.h>
#include <json-c/json.h>

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef MHD_HTTP_CONTENT_TOO_LARGE
#define MHD_HTTP_CONTENT_TOO_LARGE 413
#endif

#if defined(MHD_VERSION) && MHD_VERSION >= 0x00097000
#define MCPD_MHD_RESULT enum MHD_Result
#else
#define MCPD_MHD_RESULT int
#endif

#define MCPD_DEFAULT_PORT 8765
#define MCPD_DEFAULT_ENDPOINT "/mcp"
#define MCPD_DEFAULT_TIMEOUT_MS 30000U
#define MCPD_DEFAULT_MAX_OUTPUT (256U * 1024U)
#define MCPD_DEFAULT_MAX_REQUEST (1024U * 1024U)
#define MCPD_DEFAULT_UPGRADE_DIR "/tmp/openwrt-mcpd-upgrade"
#define MCPD_DEFAULT_MAX_FIRMWARE (16U * 1024U * 1024U)
#define MCPD_DEFAULT_FLASH_DELAY_MS 1500U
#define MCPD_PROTOCOL_VERSION "2025-11-25"
#define MCPD_SERVER_NAME "openwrt-mcpd"
#define MCPD_SERVER_VERSION "0.1.0"

struct mcpd_config {
	unsigned int port;
	char endpoint[128];
	unsigned int timeout_ms;
	size_t max_output_bytes;
	size_t max_request_bytes;
	char upgrade_dir[PATH_MAX];
	size_t max_firmware_bytes;
	unsigned int flash_delay_ms;
};

struct request_ctx {
	char *body;
	size_t len;
	bool too_large;
};

struct dynbuf {
	char *data;
	size_t len;
	size_t cap;
	bool oom;
};

struct proc_result {
	char *stdout_data;
	char *stderr_data;
	int exit_code;
	bool timed_out;
	bool truncated;
};

static volatile sig_atomic_t running = 1;

static void signal_handler(int signo)
{
	(void)signo;
	running = 0;
}

static void dynbuf_init(struct dynbuf *b)
{
	b->data = NULL;
	b->len = 0;
	b->cap = 0;
	b->oom = false;
}

static void dynbuf_free(struct dynbuf *b)
{
	free(b->data);
	dynbuf_init(b);
}

static bool dynbuf_reserve(struct dynbuf *b, size_t need)
{
	char *p;
	size_t ncap;

	if (need <= b->cap)
		return true;

	ncap = b->cap ? b->cap : 256;
	while (ncap < need) {
		if (ncap > ((size_t)-1) / 2) {
			b->oom = true;
			return false;
		}
		ncap *= 2;
	}

	p = realloc(b->data, ncap);
	if (!p) {
		b->oom = true;
		return false;
	}

	b->data = p;
	b->cap = ncap;
	return true;
}

static bool dynbuf_append(struct dynbuf *b, const char *data, size_t len)
{
	if (!len)
		return true;

	if (b->len > ((size_t)-1) - len - 1) {
		b->oom = true;
		return false;
	}

	if (!dynbuf_reserve(b, b->len + len + 1))
		return false;

	memcpy(b->data + b->len, data, len);
	b->len += len;
	b->data[b->len] = '\0';
	return true;
}

static char *xstrdup(const char *s)
{
	char *p;

	if (!s)
		s = "";
	p = malloc(strlen(s) + 1);
	if (p)
		strcpy(p, s);
	return p;
}

static unsigned long long monotonic_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ((unsigned long long)ts.tv_sec * 1000ULL) +
	       ((unsigned long long)ts.tv_nsec / 1000000ULL);
}

static bool json_get_string(json_object *obj, const char *key, const char **out)
{
	json_object *v;

	if (!json_object_object_get_ex(obj, key, &v) ||
	    !json_object_is_type(v, json_type_string))
		return false;

	*out = json_object_get_string(v);
	return true;
}

static bool json_get_object(json_object *obj, const char *key, json_object **out)
{
	json_object *v;

	if (!json_object_object_get_ex(obj, key, &v) ||
	    !json_object_is_type(v, json_type_object))
		return false;

	*out = v;
	return true;
}

static unsigned int json_get_uint_default(json_object *obj, const char *key,
					  unsigned int def, unsigned int max)
{
	json_object *v;
	int i;

	if (!json_object_object_get_ex(obj, key, &v))
		return def;

	if (!json_object_is_type(v, json_type_int))
		return def;

	i = json_object_get_int(v);
	if (i <= 0)
		return def;
	if (max && (unsigned int)i > max)
		return max;
	return (unsigned int)i;
}

static size_t json_get_size_default(json_object *obj, const char *key,
				    size_t def, size_t max)
{
	json_object *v;
	int64_t i;

	if (!json_object_object_get_ex(obj, key, &v))
		return def;

	if (!json_object_is_type(v, json_type_int))
		return def;

	i = json_object_get_int64(v);
	if (i <= 0)
		return def;
	if (max && (uint64_t)i > (uint64_t)max)
		return max;
	return (size_t)i;
}

static bool json_get_size_required(json_object *obj, const char *key, size_t *out)
{
	json_object *v;
	int64_t i;

	if (!json_object_object_get_ex(obj, key, &v) ||
	    !json_object_is_type(v, json_type_int))
		return false;

	i = json_object_get_int64(v);
	if (i < 0)
		return false;
	*out = (size_t)i;
	return true;
}

static bool json_get_bool_default(json_object *obj, const char *key, bool def)
{
	json_object *v;

	if (!json_object_object_get_ex(obj, key, &v))
		return def;
	return json_object_get_boolean(v);
}

static bool json_get_bool_required(json_object *obj, const char *key, bool *out)
{
	json_object *v;

	if (!json_object_object_get_ex(obj, key, &v) ||
	    !json_object_is_type(v, json_type_boolean))
		return false;

	*out = json_object_get_boolean(v);
	return true;
}

static char *json_to_alloc_string(json_object *obj)
{
	const char *s = json_object_to_json_string_ext(obj, JSON_C_TO_STRING_PLAIN);
	return xstrdup(s);
}

static json_object *jsonrpc_response(json_object *id, json_object *result)
{
	json_object *resp = json_object_new_object();

	json_object_object_add(resp, "jsonrpc", json_object_new_string("2.0"));
	json_object_object_add(resp, "id", id ? json_object_get(id) : NULL);
	json_object_object_add(resp, "result", result ? result : json_object_new_object());
	return resp;
}

static json_object *jsonrpc_error(json_object *id, int code, const char *message)
{
	json_object *resp = json_object_new_object();
	json_object *err = json_object_new_object();

	json_object_object_add(err, "code", json_object_new_int(code));
	json_object_object_add(err, "message", json_object_new_string(message));
	json_object_object_add(resp, "jsonrpc", json_object_new_string("2.0"));
	json_object_object_add(resp, "id", id ? json_object_get(id) : NULL);
	json_object_object_add(resp, "error", err);
	return resp;
}

static MCPD_MHD_RESULT queue_text(struct MHD_Connection *connection,
					  unsigned int status, const char *text,
					  const char *content_type)
{
	struct MHD_Response *response;
	char *buf;
	MCPD_MHD_RESULT ret;
	size_t len;

	if (!text)
		text = "";
	buf = xstrdup(text);
	if (!buf)
		return MHD_NO;

	len = strlen(buf);
	response = MHD_create_response_from_buffer(len, buf, MHD_RESPMEM_MUST_FREE);
	if (!response) {
		free(buf);
		return MHD_NO;
	}

	if (content_type)
		MHD_add_response_header(response, MHD_HTTP_HEADER_CONTENT_TYPE,
						content_type);
	ret = MHD_queue_response(connection, status, response);
	MHD_destroy_response(response);
	return ret;
}

static MCPD_MHD_RESULT queue_json_object(struct MHD_Connection *connection,
						 unsigned int status, json_object *obj)
{
	char *body = json_to_alloc_string(obj);
	MCPD_MHD_RESULT ret;

	json_object_put(obj);
	if (!body)
		return MHD_NO;
	ret = queue_text(connection, status, body, "application/json");
	free(body);
	return ret;
}

static MCPD_MHD_RESULT queue_empty(struct MHD_Connection *connection,
					   unsigned int status)
{
	return queue_text(connection, status, "", NULL);
}

static json_object *schema_string(bool required)
{
	json_object *s = json_object_new_object();
	(void)required;
	json_object_object_add(s, "type", json_object_new_string("string"));
	return s;
}

static json_object *schema_integer(void)
{
	json_object *s = json_object_new_object();
	json_object_object_add(s, "type", json_object_new_string("integer"));
	return s;
}

static json_object *schema_boolean(void)
{
	json_object *s = json_object_new_object();
	json_object_object_add(s, "type", json_object_new_string("boolean"));
	return s;
}

static json_object *schema_object(void)
{
	json_object *s = json_object_new_object();
	json_object_object_add(s, "type", json_object_new_string("object"));
	json_object_object_add(s, "additionalProperties", json_object_new_boolean(true));
	return s;
}

static json_object *new_required_array(const char *a, const char *b, const char *c)
{
	json_object *arr = json_object_new_array();

	if (a)
		json_object_array_add(arr, json_object_new_string(a));
	if (b)
		json_object_array_add(arr, json_object_new_string(b));
	if (c)
		json_object_array_add(arr, json_object_new_string(c));
	return arr;
}

static json_object *new_required_array4(const char *a, const char *b,
					const char *c, const char *d)
{
	json_object *arr = new_required_array(a, b, c);

	if (d)
		json_object_array_add(arr, json_object_new_string(d));
	return arr;
}

static json_object *tool_schema_shell(void)
{
	json_object *s = schema_object();
	json_object *props = json_object_new_object();

	json_object_object_add(props, "cmd", schema_string(true));
	json_object_object_add(props, "cwd", schema_string(false));
	json_object_object_add(props, "timeout_ms", schema_integer());
	json_object_object_add(props, "max_output_bytes", schema_integer());
	json_object_object_add(s, "properties", props);
	json_object_object_add(s, "required", new_required_array("cmd", NULL, NULL));
	return s;
}

static json_object *tool_schema_write_file(void)
{
	json_object *s = schema_object();
	json_object *props = json_object_new_object();

	json_object_object_add(props, "path", schema_string(true));
	json_object_object_add(props, "data_base64", schema_string(true));
	json_object_object_add(props, "append", schema_boolean());
	json_object_object_add(props, "mode", schema_string(false));
	json_object_object_add(s, "properties", props);
	json_object_object_add(s, "required", new_required_array("path", "data_base64", NULL));
	return s;
}

static json_object *tool_schema_ubus(void)
{
	json_object *s = schema_object();
	json_object *props = json_object_new_object();

	json_object_object_add(props, "object", schema_string(true));
	json_object_object_add(props, "method", schema_string(true));
	json_object_object_add(props, "params", schema_object());
	json_object_object_add(s, "properties", props);
	json_object_object_add(s, "required", new_required_array("object", "method", NULL));
	return s;
}

static json_object *tool_schema_device_guide(void)
{
	json_object *s = schema_object();
	json_object *props = json_object_new_object();
	json_object *topic = json_object_new_object();
	json_object *one_of = json_object_new_array();
	const char *topics[] = { "overview", "drivers", "firmware", "hgpriv", "procfs", "fmac" };
	size_t i;

	json_object_object_add(topic, "type", json_object_new_string("string"));
	for (i = 0; i < sizeof(topics) / sizeof(topics[0]); i++)
		json_object_array_add(one_of, json_object_new_string(topics[i]));
	json_object_object_add(topic, "enum", one_of);
	json_object_object_add(props, "topic", topic);
	json_object_object_add(s, "properties", props);
	return s;
}

static json_object *tool_schema_firmware_upload_begin(void)
{
	json_object *s = schema_object();
	json_object *props = json_object_new_object();

	json_object_object_add(props, "upload_id", schema_string(true));
	json_object_object_add(props, "total_bytes", schema_integer());
	json_object_object_add(props, "sha256", schema_string(true));
	json_object_object_add(s, "properties", props);
	json_object_object_add(s, "required", new_required_array("upload_id", "total_bytes", "sha256"));
	return s;
}

static json_object *tool_schema_firmware_upload_chunk(void)
{
	json_object *s = schema_object();
	json_object *props = json_object_new_object();

	json_object_object_add(props, "upload_id", schema_string(true));
	json_object_object_add(props, "offset", schema_integer());
	json_object_object_add(props, "data_base64", schema_string(true));
	json_object_object_add(s, "properties", props);
	json_object_object_add(s, "required", new_required_array("upload_id", "offset", "data_base64"));
	return s;
}

static json_object *tool_schema_firmware_validate(void)
{
	json_object *s = schema_object();
	json_object *props = json_object_new_object();

	json_object_object_add(props, "upload_id", schema_string(true));
	json_object_object_add(props, "keep_config", schema_boolean());
	json_object_object_add(s, "properties", props);
	json_object_object_add(s, "required", new_required_array("upload_id", NULL, NULL));
	return s;
}

static json_object *tool_schema_firmware_flash(void)
{
	json_object *s = schema_object();
	json_object *props = json_object_new_object();

	json_object_object_add(props, "upload_id", schema_string(true));
	json_object_object_add(props, "allow_reboot", schema_boolean());
	json_object_object_add(props, "keep_config", schema_boolean());
	json_object_object_add(props, "force", schema_boolean());
	json_object_object_add(s, "properties", props);
	json_object_object_add(s, "required", new_required_array4("upload_id", "allow_reboot", NULL, NULL));
	return s;
}

static json_object *tool_schema_firmware_status(void)
{
	json_object *s = schema_object();
	json_object *props = json_object_new_object();

	json_object_object_add(props, "upload_id", schema_string(true));
	json_object_object_add(s, "properties", props);
	json_object_object_add(s, "required", new_required_array("upload_id", NULL, NULL));
	return s;
}

static json_object *new_tool(const char *name, const char *description,
				     json_object *schema)
{
	json_object *tool = json_object_new_object();

	json_object_object_add(tool, "name", json_object_new_string(name));
	json_object_object_add(tool, "description", json_object_new_string(description));
	json_object_object_add(tool, "inputSchema", schema);
	return tool;
}

static const char *board_instructions(void)
{
	return "HugeIC MT7628AN development board helper. Driver modules are staged in /test_ko, firmware in /test_firmware, and /lib/firmware may contain symlinks into /test_firmware. The existing rpcd object is luci.test_driver. Use hgpriv <ifname> set key=value or get key for FMAC tuning; frequency values use MHz x10 units, e.g. 908 MHz -> 9080 and 908.5 MHz -> 9085, while freq_range bandwidth remains MHz. After loading hgicf.ko, inspect /proc/hgicf/status and related procfs nodes.";
}

static const char *guide_for_topic(const char *topic)
{
	if (!topic || !strcmp(topic, "overview"))
		return "# HugeIC board overview\n\n"
		       "This MCP daemon intentionally provides full-access development-board tools. It is not authenticated or sandboxed.\n\n"
		       "Key paths:\n"
		       "- `/test_ko` stores uploaded `.ko` kernel modules.\n"
		       "- `/test_firmware` stores firmware files.\n"
		       "- `/lib/firmware` may contain symlinks into `/test_firmware`.\n"
		       "- Existing rpcd object: `luci.test_driver`.\n\n"
		       "Useful topics: `drivers`, `firmware`, `hgpriv`, `procfs`, `fmac`.\n"
		       "Host driver source reference only: `/home/matt/hugeic/huge-ic-driver`; do not assume it exists on the device.\n";

	if (!strcmp(topic, "drivers"))
		return "# Driver modules\n\n"
		       "Upload `.ko` files to `/test_ko`. The LuCI/rpcd backend object available on the board is `luci.test_driver`.\n\n"
		       "Examples:\n"
		       "```sh\n"
		       "ubus call luci.test_driver list_modules '{}'\n"
		       "ubus call luci.test_driver load_module '{\"filename\":\"hgicf.ko\",\"args\":\"\"}'\n"
		       "ubus call luci.test_driver unload_module '{\"name\":\"hgicf\"}'\n"
		       "```\n\n"
		       "After `hgicf.ko` is loaded, inspect `/proc/hgicf/status` and related procfs entries.\n";

	if (!strcmp(topic, "firmware"))
		return "# Firmware files\n\n"
		       "Firmware payloads are stored in `/test_firmware`. The board may expose them to drivers through symlinks in `/lib/firmware`.\n\n"
		       "Examples:\n"
		       "```sh\n"
		       "ubus call luci.test_driver list_firmwares '{}'\n"
		       "ubus call luci.test_driver create_symlink '{\"filename\":\"fw.bin\",\"linkname\":\"fw.bin\"}'\n"
		       "```\n";

	if (!strcmp(topic, "hgpriv"))
		return "# hgpriv\n\n"
		       "Use `hgpriv <ifname> set key=value` and `hgpriv <ifname> get key` for HugeIC private driver settings.\n\n"
		       "Examples:\n"
		       "```sh\n"
		       "hgpriv wlan0 get ssid\n"
		       "hgpriv wlan0 set txpower=15\n"
		       "```\n\n"
		       "Frequency values are passed to `hgpriv` in MHz x10 units: `908` MHz becomes `9080`, and `908.5` MHz becomes `9085`. `freq_range` bandwidth remains in MHz.\n";

	if (!strcmp(topic, "procfs"))
		return "# procfs\n\n"
		       "After `hgicf.ko` is loaded, useful procfs nodes include:\n"
		       "- `/proc/hgicf/status`\n"
		       "- `/proc/hgicf/iwpriv`\n"
		       "- `/proc/hgicf/fwevnt`\n"
		       "- `/proc/hgicf/ota` when OTA is enabled\n"
		       "- sometimes `/proc/<ifname>/status`\n\n"
		       "Examples:\n"
		       "```sh\n"
		       "cat /proc/hgicf/status\n"
		       "echo \"wlan0 get ssid\" > /proc/hgicf/iwpriv\n"
		       "echo \"wlan0 set txpower=15\" > /proc/hgicf/iwpriv\n"
		       "```\n";

	if (!strcmp(topic, "fmac"))
		return "# FMAC quick notes\n\n"
		       "FMAC settings can be driven with `hgpriv <ifname> set key=value` and inspected with `hgpriv <ifname> get key`.\n"
		       "Remember the frequency conversion used by driver tools: MHz values become x10 integer units (`908` -> `9080`, `908.5` -> `9085`), while `freq_range` bandwidth remains MHz.\n"
		       "For low-level procfs control after loading `hgicf.ko`, use `/proc/hgicf/iwpriv`, for example `echo \"wlan0 set txpower=15\" > /proc/hgicf/iwpriv`.\n";

	return "# Unknown topic\n\nKnown topics: `overview`, `drivers`, `firmware`, `hgpriv`, `procfs`, `fmac`.\n";
}

static void proc_result_free(struct proc_result *r)
{
	free(r->stdout_data);
	free(r->stderr_data);
	r->stdout_data = NULL;
	r->stderr_data = NULL;
}

static void append_limited(struct dynbuf *target, const char *buf, size_t len,
				   size_t *stored_total, size_t max_output, bool *truncated)
{
	size_t room;

	if (*stored_total >= max_output) {
		if (len)
			*truncated = true;
		return;
	}

	room = max_output - *stored_total;
	if (len > room) {
		len = room;
		*truncated = true;
	}

	if (!dynbuf_append(target, buf, len))
		*truncated = true;
	*stored_total += len;
}

static int set_nonblock(int fd)
{
	int flags = fcntl(fd, F_GETFL, 0);

	if (flags < 0)
		return -1;
	return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static void close_pipe_fd(int *fd, bool *openp)
{
	if (*fd >= 0) {
		close(*fd);
		*fd = -1;
	}
	*openp = false;
}

static void kill_process_group(pid_t pid)
{
	/*
	 * Kill both the process group and the direct child.  The positive-pid kill
	 * covers commands that change their own process group before timeout; the
	 * process-group kill covers normal shell grandchildren holding pipe fds.
	 */
	if (pid > 0) {
		kill(-pid, SIGKILL);
		kill(pid, SIGKILL);
	}
}

static int run_process(char *const argv[], const char *cwd,
			       unsigned int timeout_ms, size_t max_output,
			       struct proc_result *out)
{
	int out_pipe[2] = { -1, -1 };
	int err_pipe[2] = { -1, -1 };
	pid_t pid;
	struct dynbuf stdout_buf, stderr_buf;
	size_t stored_total = 0;
	bool stdout_open = true, stderr_open = true;
	unsigned long long start, deadline;
	unsigned long long kill_deadline = 0;
	int status = 0;

	memset(out, 0, sizeof(*out));
	out->exit_code = -1;
	dynbuf_init(&stdout_buf);
	dynbuf_init(&stderr_buf);

	if (pipe(out_pipe) < 0 || pipe(err_pipe) < 0)
		goto fail;

	pid = fork();
	if (pid < 0)
		goto fail;

	if (pid == 0) {
		if (setpgid(0, 0) < 0) {
			perror("setpgid");
			_exit(127);
		}

		close(out_pipe[0]);
		close(err_pipe[0]);
		dup2(out_pipe[1], STDOUT_FILENO);
		dup2(err_pipe[1], STDERR_FILENO);
		close(out_pipe[1]);
		close(err_pipe[1]);

		if (cwd && *cwd && chdir(cwd) < 0) {
			perror("chdir");
			_exit(127);
		}

		execvp(argv[0], argv);
		perror("execvp");
		_exit(127);
	}

	/* Avoid a race where the child execs before the process group is set. */
	setpgid(pid, pid);

	close(out_pipe[1]);
	close(err_pipe[1]);
	out_pipe[1] = -1;
	err_pipe[1] = -1;
	set_nonblock(out_pipe[0]);
	set_nonblock(err_pipe[0]);

	start = monotonic_ms();
	deadline = start + timeout_ms;

	while (stdout_open || stderr_open) {
		struct pollfd fds[2];
		int nfds = 0;
		int timeout;
		unsigned long long now = monotonic_ms();

		if (!out->timed_out && now >= deadline) {
			kill_process_group(pid);
			out->timed_out = true;
			kill_deadline = now + 1000ULL;
		}

		if (out->timed_out && kill_deadline && now >= kill_deadline) {
			close_pipe_fd(&out_pipe[0], &stdout_open);
			close_pipe_fd(&err_pipe[0], &stderr_open);
			break;
		}

		if (stdout_open) {
			fds[nfds].fd = out_pipe[0];
			fds[nfds].events = POLLIN | POLLHUP | POLLERR;
			fds[nfds].revents = 0;
			nfds++;
		}
		if (stderr_open) {
			fds[nfds].fd = err_pipe[0];
			fds[nfds].events = POLLIN | POLLHUP | POLLERR;
			fds[nfds].revents = 0;
			nfds++;
		}

		now = monotonic_ms();
		if (out->timed_out || now >= deadline)
			timeout = 100;
		else {
			unsigned long long left = deadline - now;
			timeout = left > 1000ULL ? 1000 : (int)left;
		}

		if (poll(fds, nfds, timeout) < 0) {
			if (errno == EINTR)
				continue;
			break;
		}

		for (int i = 0; i < nfds; i++) {
			char buf[4096];
			struct dynbuf *target;
			bool *openp;
			ssize_t n;

			if (!fds[i].revents)
				continue;

			target = (fds[i].fd == out_pipe[0]) ? &stdout_buf : &stderr_buf;
			openp = (fds[i].fd == out_pipe[0]) ? &stdout_open : &stderr_open;

			for (;;) {
				n = read(fds[i].fd, buf, sizeof(buf));
				if (n > 0) {
					append_limited(target, buf, (size_t)n, &stored_total,
						       max_output, &out->truncated);
					continue;
				}
				if (n == 0) {
					*openp = false;
					close(fds[i].fd);
					if (fds[i].fd == out_pipe[0])
						out_pipe[0] = -1;
					else
						err_pipe[0] = -1;
				}
				break;
			}
		}
	}

	while (waitpid(pid, &status, 0) < 0 && errno == EINTR)
		;

	if (WIFEXITED(status))
		out->exit_code = WEXITSTATUS(status);
	else if (WIFSIGNALED(status))
		out->exit_code = 128 + WTERMSIG(status);

	out->stdout_data = stdout_buf.data ? stdout_buf.data : xstrdup("");
	out->stderr_data = stderr_buf.data ? stderr_buf.data : xstrdup("");
	return 0;

fail:
	if (out_pipe[0] >= 0)
		close(out_pipe[0]);
	if (out_pipe[1] >= 0)
		close(out_pipe[1]);
	if (err_pipe[0] >= 0)
		close(err_pipe[0]);
	if (err_pipe[1] >= 0)
		close(err_pipe[1]);
	dynbuf_free(&stdout_buf);
	dynbuf_free(&stderr_buf);
	out->stdout_data = xstrdup("");
	out->stderr_data = xstrdup(strerror(errno));
	out->exit_code = -1;
	return -1;
}

static int b64_value(unsigned char c)
{
	if (c >= 'A' && c <= 'Z')
		return c - 'A';
	if (c >= 'a' && c <= 'z')
		return c - 'a' + 26;
	if (c >= '0' && c <= '9')
		return c - '0' + 52;
	if (c == '+')
		return 62;
	if (c == '/')
		return 63;
	return -1;
}

static bool decode_base64(const char *in, unsigned char **out, size_t *out_len)
{
	struct dynbuf b;
	int val = 0, valb = -8;
	bool pad = false;

	dynbuf_init(&b);

	for (; *in; in++) {
		unsigned char c = (unsigned char)*in;
		int d;

		if (c == ' ' || c == '\n' || c == '\r' || c == '\t')
			continue;
		if (c == '=') {
			pad = true;
			continue;
		}
		if (pad)
			goto fail;

		d = b64_value(c);
		if (d < 0)
			goto fail;
		val = (val << 6) | d;
		valb += 6;
		if (valb >= 0) {
			char outc = (char)((val >> valb) & 0xff);
			if (!dynbuf_append(&b, &outc, 1))
				goto fail;
			valb -= 8;
		}
	}

	*out = (unsigned char *)b.data;
	*out_len = b.len;
	return true;

fail:
	dynbuf_free(&b);
	*out = NULL;
	*out_len = 0;
	return false;
}

static bool parse_mode(json_object *args, mode_t *mode)
{
	json_object *v;
	const char *s;
	char *end;
	long n;

	if (!json_object_object_get_ex(args, "mode", &v))
		return false;

	if (json_object_is_type(v, json_type_int)) {
		n = json_object_get_int(v);
	} else if (json_object_is_type(v, json_type_string)) {
		s = json_object_get_string(v);
		errno = 0;
		n = strtol(s, &end, 8);
		if (errno || *end)
			return false;
	} else {
		return false;
	}

	if (n < 0 || n > 07777)
		return false;
	*mode = (mode_t)n;
	return true;
}

static json_object *tool_result(const char *text, json_object *structured,
					bool is_error)
{
	json_object *result = json_object_new_object();
	json_object *content = json_object_new_array();
	json_object *item = json_object_new_object();

	json_object_object_add(item, "type", json_object_new_string("text"));
	json_object_object_add(item, "text", json_object_new_string(text ? text : ""));
	json_object_array_add(content, item);
	json_object_object_add(result, "content", content);
	if (structured)
		json_object_object_add(result, "structuredContent", structured);
	if (is_error)
		json_object_object_add(result, "isError", json_object_new_boolean(true));
	return result;
}

static json_object *tool_error(const char *message)
{
	json_object *structured = json_object_new_object();
	json_object_object_add(structured, "error", json_object_new_string(message));
	return tool_result(message, structured, true);
}

static json_object *proc_structured(struct proc_result *r)
{
	json_object *structured = json_object_new_object();

	json_object_object_add(structured, "stdout", json_object_new_string(r->stdout_data ? r->stdout_data : ""));
	json_object_object_add(structured, "stderr", json_object_new_string(r->stderr_data ? r->stderr_data : ""));
	json_object_object_add(structured, "exit_code", json_object_new_int(r->exit_code));
	json_object_object_add(structured, "timed_out", json_object_new_boolean(r->timed_out));
	json_object_object_add(structured, "truncated", json_object_new_boolean(r->truncated));
	return structured;
}

static bool write_all_fd(int fd, const void *data, size_t len)
{
	const unsigned char *p = data;

	while (len) {
		ssize_t n = write(fd, p, len);

		if (n < 0) {
			if (errno == EINTR)
				continue;
			return false;
		}
		if (n == 0)
			return false;
		p += n;
		len -= (size_t)n;
	}
	return true;
}

static bool read_small_file(const char *path, size_t max_len, char **out)
{
	int fd;
	struct dynbuf b;
	char tmp[1024];
	bool ok = false;

	*out = NULL;
	fd = open(path, O_RDONLY);
	if (fd < 0)
		return false;

	dynbuf_init(&b);
	for (;;) {
		ssize_t n = read(fd, tmp, sizeof(tmp));

		if (n < 0) {
			if (errno == EINTR)
				continue;
			break;
		}
		if (n == 0) {
			ok = true;
			break;
		}
		if (b.len + (size_t)n > max_len)
			break;
		if (!dynbuf_append(&b, tmp, (size_t)n))
			break;
	}
	close(fd);

	if (!ok) {
		dynbuf_free(&b);
		return false;
	}
	*out = b.data ? b.data : xstrdup("");
	return *out != NULL;
}

static bool write_json_file(const char *path, json_object *obj)
{
	const char *s = json_object_to_json_string_ext(obj, JSON_C_TO_STRING_PLAIN);
	int fd;
	bool ok;

	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd < 0)
		return false;
	ok = write_all_fd(fd, s, strlen(s)) && write_all_fd(fd, "\n", 1);
	if (close(fd) < 0)
		ok = false;
	return ok;
}

static json_object *read_json_file(const char *path)
{
	char *data;
	json_object *obj;

	if (!read_small_file(path, 1024U * 1024U, &data))
		return NULL;
	obj = json_tokener_parse(data);
	free(data);
	return obj;
}

static bool mkdir_p(const char *path, mode_t mode)
{
	char tmp[PATH_MAX];
	size_t len;

	if (!path || !path[0] || strlen(path) >= sizeof(tmp))
		return false;

	strcpy(tmp, path);
	len = strlen(tmp);
	if (len > 1 && tmp[len - 1] == '/')
		tmp[len - 1] = '\0';

	for (char *p = tmp + 1; *p; p++) {
		if (*p != '/')
			continue;
		*p = '\0';
		if (mkdir(tmp, mode) < 0 && errno != EEXIST)
			return false;
		*p = '/';
	}

	if (mkdir(tmp, mode) < 0 && errno != EEXIST)
		return false;
	return true;
}

static bool ensure_upgrade_dir(struct mcpd_config *cfg)
{
	struct stat st;

	if (!mkdir_p(cfg->upgrade_dir, 0700))
		return false;
	if (stat(cfg->upgrade_dir, &st) < 0)
		return false;
	return S_ISDIR(st.st_mode);
}

static bool valid_upload_id(const char *id)
{
	size_t len;

	if (!id)
		return false;
	len = strlen(id);
	if (!len || len > 64)
		return false;
	if (!strcmp(id, ".") || !strcmp(id, ".."))
		return false;

	for (size_t i = 0; i < len; i++) {
		char c = id[i];

		if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
		    (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.')
			continue;
		return false;
	}
	return true;
}

static bool firmware_paths(struct mcpd_config *cfg, const char *upload_id,
			   char *image, size_t image_len,
			   char *meta, size_t meta_len,
			   char *log, size_t log_len)
{
	if (!valid_upload_id(upload_id))
		return false;

	if (image && snprintf(image, image_len, "%s/%s.bin",
			      cfg->upgrade_dir, upload_id) >= (int)image_len)
		return false;
	if (meta && snprintf(meta, meta_len, "%s/%s.json",
			     cfg->upgrade_dir, upload_id) >= (int)meta_len)
		return false;
	if (log && snprintf(log, log_len, "%s/%s.log",
			    cfg->upgrade_dir, upload_id) >= (int)log_len)
		return false;
	return true;
}

static bool is_sha256_hex(const char *s)
{
	if (!s || strlen(s) != 64)
		return false;

	for (size_t i = 0; i < 64; i++) {
		char c = s[i];

		if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
		    (c >= 'A' && c <= 'F'))
			continue;
		return false;
	}
	return true;
}

static bool starts_with_sha256_hex(const char *s)
{
	if (!s)
		return false;

	for (size_t i = 0; i < 64; i++) {
		char c = s[i];

		if (!c)
			return false;
		if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
		    (c >= 'A' && c <= 'F'))
			continue;
		return false;
	}
	return s[64] == '\0' || s[64] == ' ' || s[64] == '\t' || s[64] == '\n';
}

static void lowercase_sha256(char out[65], const char *in)
{
	for (size_t i = 0; i < 64; i++) {
		char c = in[i];

		if (c >= 'A' && c <= 'F')
			c = (char)(c - 'A' + 'a');
		out[i] = c;
	}
	out[64] = '\0';
}

static bool file_size(const char *path, size_t *out)
{
	struct stat st;

	if (stat(path, &st) < 0 || st.st_size < 0)
		return false;
	*out = (size_t)st.st_size;
	return true;
}

static bool meta_get_size(json_object *meta, const char *key, size_t *out)
{
	json_object *v;
	int64_t i;

	if (!json_object_object_get_ex(meta, key, &v) ||
	    !json_object_is_type(v, json_type_int))
		return false;
	i = json_object_get_int64(v);
	if (i < 0)
		return false;
	*out = (size_t)i;
	return true;
}

static int meta_get_int(json_object *meta, const char *key, int def)
{
	json_object *v;

	if (!json_object_object_get_ex(meta, key, &v) ||
	    !json_object_is_type(v, json_type_int))
		return def;
	return json_object_get_int(v);
}

static bool meta_get_bool(json_object *meta, const char *key, bool def)
{
	json_object *v;

	if (!json_object_object_get_ex(meta, key, &v))
		return def;
	return json_object_get_boolean(v);
}

static const char *meta_get_string(json_object *meta, const char *key)
{
	json_object *v;

	if (!json_object_object_get_ex(meta, key, &v) ||
	    !json_object_is_type(v, json_type_string))
		return "";
	return json_object_get_string(v);
}

static bool sha256_file(const char *path, char out[65], struct mcpd_config *cfg,
			char *err, size_t err_len)
{
	char *argv[3];
	struct proc_result r;
	bool ok = false;
	const char *s;

	argv[0] = "sha256sum";
	argv[1] = (char *)path;
	argv[2] = NULL;
	run_process(argv, NULL, cfg->timeout_ms, 4096, &r);

	if (r.exit_code != 0 || r.timed_out) {
		snprintf(err, err_len, "sha256sum failed: %s",
			 r.stderr_data ? r.stderr_data : "");
		goto out;
	}

	s = r.stdout_data ? r.stdout_data : "";
	if (!starts_with_sha256_hex(s)) {
		snprintf(err, err_len, "sha256sum output did not start with a SHA256 digest");
		goto out;
	}

	lowercase_sha256(out, s);
	ok = true;

out:
	proc_result_free(&r);
	return ok;
}

static char *file_tail(const char *path, size_t max_len)
{
	int fd;
	struct stat st;
	off_t off = 0;
	char *buf;
	size_t len;
	ssize_t n;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return xstrdup("");

	if (fstat(fd, &st) < 0) {
		close(fd);
		return xstrdup("");
	}
	if (st.st_size > (off_t)max_len)
		off = st.st_size - (off_t)max_len;
	if (off && lseek(fd, off, SEEK_SET) < 0) {
		close(fd);
		return xstrdup("");
	}

	len = st.st_size > (off_t)max_len ? max_len : (size_t)st.st_size;
	buf = calloc(1, len + 1);
	if (!buf) {
		close(fd);
		return NULL;
	}

	n = read(fd, buf, len);
	close(fd);
	if (n < 0) {
		free(buf);
		return xstrdup("");
	}
	buf[n] = '\0';
	return buf;
}

static bool validation_bool(json_object *validation, const char *key, bool def)
{
	json_object *v;

	if (!validation || !json_object_object_get_ex(validation, key, &v))
		return def;
	return json_object_get_boolean(v);
}

static bool schedule_sysupgrade(const char *image, const char *log_path,
				bool keep_config, bool force, unsigned int delay_ms,
				pid_t *scheduled_pid)
{
	pid_t pid;

	pid = fork();
	if (pid < 0)
		return false;

	if (pid == 0) {
		pid_t child;

		if (setsid() < 0)
			_exit(127);
		child = fork();
		if (child < 0)
			_exit(127);
		if (child > 0)
			_exit(0);

		if (delay_ms)
			usleep(delay_ms * 1000U);

		int nullfd = open("/dev/null", O_RDONLY);
		if (nullfd >= 0) {
			dup2(nullfd, STDIN_FILENO);
			close(nullfd);
		}

		int logfd = open(log_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
		if (logfd >= 0) {
			dup2(logfd, STDOUT_FILENO);
			dup2(logfd, STDERR_FILENO);
			close(logfd);
		}

		char *argv[6];
		int i = 0;

		argv[i++] = "/sbin/sysupgrade";
		if (force)
			argv[i++] = "-F";
		if (!keep_config)
			argv[i++] = "-n";
		argv[i++] = (char *)image;
		argv[i] = NULL;
		execv(argv[0], argv);
		_exit(127);
	}

	while (waitpid(pid, NULL, 0) < 0 && errno == EINTR)
		;
	if (scheduled_pid)
		*scheduled_pid = pid;
	return true;
}

static json_object *call_shell(json_object *args, struct mcpd_config *cfg)
{
	const char *cmd, *cwd = NULL;
	unsigned int timeout_ms;
	size_t max_output;
	char *argv[4];
	struct proc_result r;
	json_object *structured;
	struct dynbuf text;
	json_object *result;

	if (!json_get_string(args, "cmd", &cmd) || !cmd[0])
		return tool_error("shell requires non-empty string argument 'cmd'");
	json_get_string(args, "cwd", &cwd);
	timeout_ms = json_get_uint_default(args, "timeout_ms", cfg->timeout_ms, cfg->timeout_ms);
	max_output = json_get_size_default(args, "max_output_bytes", cfg->max_output_bytes,
				       cfg->max_output_bytes);

	argv[0] = "/bin/sh";
	argv[1] = "-c";
	argv[2] = (char *)cmd;
	argv[3] = NULL;
	run_process(argv, cwd, timeout_ms, max_output, &r);

	structured = proc_structured(&r);
	dynbuf_init(&text);
	dynbuf_append(&text, "exit_code=", 10);
	char codebuf[64];
	snprintf(codebuf, sizeof(codebuf), "%d timed_out=%s truncated=%s\n\nstdout:\n",
		 r.exit_code, r.timed_out ? "true" : "false", r.truncated ? "true" : "false");
	dynbuf_append(&text, codebuf, strlen(codebuf));
	dynbuf_append(&text, r.stdout_data ? r.stdout_data : "", strlen(r.stdout_data ? r.stdout_data : ""));
	dynbuf_append(&text, "\n\nstderr:\n", 10);
	dynbuf_append(&text, r.stderr_data ? r.stderr_data : "", strlen(r.stderr_data ? r.stderr_data : ""));

	result = tool_result(text.data ? text.data : "", structured, false);
	dynbuf_free(&text);
	proc_result_free(&r);
	return result;
}

static json_object *call_write_file(json_object *args)
{
	const char *path, *data_b64;
	unsigned char *data = NULL;
	size_t data_len = 0, off = 0;
	bool append = false;
	json_object *v;
	int flags, fd;
	mode_t mode = 0644;
	bool have_mode;
	json_object *structured;
	char text[256];
	char modebuf[16];

	if (!json_get_string(args, "path", &path) || !path[0])
		return tool_error("write_file_base64 requires non-empty string argument 'path'");
	if (!json_get_string(args, "data_base64", &data_b64))
		return tool_error("write_file_base64 requires string argument 'data_base64'");
	if (json_object_object_get_ex(args, "append", &v))
		append = json_object_get_boolean(v);
	have_mode = parse_mode(args, &mode);
	if (json_object_object_get_ex(args, "mode", &v) && !have_mode)
		return tool_error("invalid mode; use an octal string such as '0644' or integer <= 07777");

	if (!decode_base64(data_b64, &data, &data_len))
		return tool_error("invalid base64 data");

	flags = O_WRONLY | O_CREAT | (append ? O_APPEND : O_TRUNC);
	fd = open(path, flags, mode);
	if (fd < 0) {
		free(data);
		snprintf(text, sizeof(text), "open failed: %s", strerror(errno));
		return tool_error(text);
	}

	while (off < data_len) {
		ssize_t n = write(fd, data + off, data_len - off);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			close(fd);
			free(data);
			snprintf(text, sizeof(text), "write failed: %s", strerror(errno));
			return tool_error(text);
		}
		off += (size_t)n;
	}

	if (close(fd) < 0) {
		free(data);
		snprintf(text, sizeof(text), "close failed: %s", strerror(errno));
		return tool_error(text);
	}

	if (have_mode && chmod(path, mode) < 0) {
		free(data);
		snprintf(text, sizeof(text), "chmod failed: %s", strerror(errno));
		return tool_error(text);
	}

	structured = json_object_new_object();
	json_object_object_add(structured, "path", json_object_new_string(path));
	json_object_object_add(structured, "bytes_written", json_object_new_int64((int64_t)data_len));
	json_object_object_add(structured, "append", json_object_new_boolean(append));
	if (have_mode) {
		snprintf(modebuf, sizeof(modebuf), "%04o", (unsigned int)mode);
		json_object_object_add(structured, "mode", json_object_new_string(modebuf));
	}

	snprintf(text, sizeof(text), "wrote %lu bytes to %s", (unsigned long)data_len, path);
	free(data);
	return tool_result(text, structured, false);
}

static json_object *call_ubus(json_object *args, struct mcpd_config *cfg)
{
	const char *object, *method;
	json_object *params = NULL;
	char *params_s;
	char *argv[6];
	struct proc_result r;
	json_object *structured, *parsed;
	struct dynbuf text;
	json_object *result;

	if (!json_get_string(args, "object", &object) || !object[0])
		return tool_error("ubus_call requires non-empty string argument 'object'");
	if (!json_get_string(args, "method", &method) || !method[0])
		return tool_error("ubus_call requires non-empty string argument 'method'");

	if (!json_get_object(args, "params", &params))
		params = json_object_new_object();
	else
		json_object_get(params);
	params_s = json_to_alloc_string(params);
	json_object_put(params);
	if (!params_s)
		return tool_error("failed to serialize ubus params");

	argv[0] = "ubus";
	argv[1] = "call";
	argv[2] = (char *)object;
	argv[3] = (char *)method;
	argv[4] = params_s;
	argv[5] = NULL;
	run_process(argv, NULL, cfg->timeout_ms, cfg->max_output_bytes, &r);
	free(params_s);

	structured = proc_structured(&r);
	parsed = json_tokener_parse(r.stdout_data ? r.stdout_data : "");
	if (parsed)
		json_object_object_add(structured, "json", parsed);

	dynbuf_init(&text);
	char codebuf[64];
	snprintf(codebuf, sizeof(codebuf), "ubus exit_code=%d timed_out=%s truncated=%s\n\nstdout:\n",
		 r.exit_code, r.timed_out ? "true" : "false", r.truncated ? "true" : "false");
	dynbuf_append(&text, codebuf, strlen(codebuf));
	dynbuf_append(&text, r.stdout_data ? r.stdout_data : "", strlen(r.stdout_data ? r.stdout_data : ""));
	dynbuf_append(&text, "\n\nstderr:\n", 10);
	dynbuf_append(&text, r.stderr_data ? r.stderr_data : "", strlen(r.stderr_data ? r.stderr_data : ""));

	result = tool_result(text.data ? text.data : "", structured, false);
	dynbuf_free(&text);
	proc_result_free(&r);
	return result;
}

static json_object *call_device_guide(json_object *args)
{
	const char *topic = "overview";
	json_object *structured;
	const char *guide;

	json_get_string(args, "topic", &topic);
	if (strcmp(topic, "overview") && strcmp(topic, "drivers") &&
	    strcmp(topic, "firmware") && strcmp(topic, "hgpriv") &&
	    strcmp(topic, "procfs") && strcmp(topic, "fmac"))
		return tool_error("unknown device_guide topic; use overview, drivers, firmware, hgpriv, procfs, or fmac");
	guide = guide_for_topic(topic);
	structured = json_object_new_object();
	json_object_object_add(structured, "topic", json_object_new_string(topic));
	json_object_object_add(structured, "markdown", json_object_new_string(guide));
	return tool_result(guide, structured, false);
}

static json_object *call_firmware_upload_begin(json_object *args, struct mcpd_config *cfg)
{
	const char *upload_id, *sha_arg;
	char sha[65];
	size_t total_bytes;
	char image[PATH_MAX], meta_path[PATH_MAX], log_path[PATH_MAX];
	int fd;
	json_object *meta, *structured;
	char text[256];

	if (!json_get_string(args, "upload_id", &upload_id) || !valid_upload_id(upload_id))
		return tool_error("firmware_upload_begin requires a safe upload_id using letters, digits, '.', '_' or '-'");
	if (!json_get_size_required(args, "total_bytes", &total_bytes) || total_bytes == 0)
		return tool_error("firmware_upload_begin requires positive integer total_bytes");
	if (total_bytes > cfg->max_firmware_bytes)
		return tool_error("firmware image exceeds configured max_firmware_bytes");
	if (!json_get_string(args, "sha256", &sha_arg) || !is_sha256_hex(sha_arg))
		return tool_error("firmware_upload_begin requires 64-character hex sha256");
	lowercase_sha256(sha, sha_arg);

	if (!ensure_upgrade_dir(cfg))
		return tool_error("failed to create firmware upgrade directory");
	if (!firmware_paths(cfg, upload_id, image, sizeof(image), meta_path, sizeof(meta_path),
			    log_path, sizeof(log_path)))
		return tool_error("failed to build firmware upload paths");

	fd = open(image, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd < 0) {
		snprintf(text, sizeof(text), "failed to create firmware image: %s", strerror(errno));
		return tool_error(text);
	}
	if (close(fd) < 0) {
		snprintf(text, sizeof(text), "failed to close firmware image: %s", strerror(errno));
		return tool_error(text);
	}
	unlink(log_path);

	meta = json_object_new_object();
	json_object_object_add(meta, "upload_id", json_object_new_string(upload_id));
	json_object_object_add(meta, "image_path", json_object_new_string(image));
	json_object_object_add(meta, "log_path", json_object_new_string(log_path));
	json_object_object_add(meta, "total_bytes", json_object_new_int64((int64_t)total_bytes));
	json_object_object_add(meta, "received_bytes", json_object_new_int64(0));
	json_object_object_add(meta, "expected_sha256", json_object_new_string(sha));
	json_object_object_add(meta, "complete", json_object_new_boolean(false));
	json_object_object_add(meta, "validated", json_object_new_boolean(false));
	json_object_object_add(meta, "flash_scheduled", json_object_new_boolean(false));
	if (!write_json_file(meta_path, meta)) {
		json_object_put(meta);
		return tool_error("failed to write firmware upload metadata");
	}

	structured = json_object_new_object();
	json_object_object_add(structured, "upload_id", json_object_new_string(upload_id));
	json_object_object_add(structured, "path", json_object_new_string(image));
	json_object_object_add(structured, "total_bytes", json_object_new_int64((int64_t)total_bytes));
	json_object_object_add(structured, "sha256", json_object_new_string(sha));
	json_object_object_add(structured, "max_firmware_bytes",
			       json_object_new_int64((int64_t)cfg->max_firmware_bytes));
	snprintf(text, sizeof(text), "created firmware upload %s for %lu bytes",
		 upload_id, (unsigned long)total_bytes);
	json_object_put(meta);
	return tool_result(text, structured, false);
}

static json_object *call_firmware_upload_chunk(json_object *args, struct mcpd_config *cfg)
{
	const char *upload_id, *data_b64, *expected_sha;
	unsigned char *data = NULL;
	size_t data_len = 0, offset, received, total, actual_size;
	char image[PATH_MAX], meta_path[PATH_MAX], log_path[PATH_MAX];
	char actual_sha[65], err[256], text[256];
	json_object *meta, *structured;
	int fd;
	bool complete;

	if (!json_get_string(args, "upload_id", &upload_id) || !valid_upload_id(upload_id))
		return tool_error("firmware_upload_chunk requires a safe upload_id");
	if (!json_get_size_required(args, "offset", &offset))
		return tool_error("firmware_upload_chunk requires integer offset");
	if (!json_get_string(args, "data_base64", &data_b64))
		return tool_error("firmware_upload_chunk requires string data_base64");
	if (!decode_base64(data_b64, &data, &data_len))
		return tool_error("invalid base64 data");

	if (!firmware_paths(cfg, upload_id, image, sizeof(image), meta_path, sizeof(meta_path),
			    log_path, sizeof(log_path))) {
		free(data);
		return tool_error("failed to build firmware upload paths");
	}
	meta = read_json_file(meta_path);
	if (!meta) {
		free(data);
		return tool_error("firmware upload metadata not found; call firmware_upload_begin first");
	}
	if (!meta_get_size(meta, "received_bytes", &received) ||
	    !meta_get_size(meta, "total_bytes", &total)) {
		json_object_put(meta);
		free(data);
		return tool_error("firmware upload metadata is invalid");
	}
	expected_sha = meta_get_string(meta, "expected_sha256");
	if (!file_size(image, &actual_size)) {
		json_object_put(meta);
		free(data);
		return tool_error("firmware image file is missing");
	}
	if (offset != received || actual_size != received) {
		snprintf(text, sizeof(text), "offset mismatch: expected %lu, got %lu",
			 (unsigned long)received, (unsigned long)offset);
		json_object_put(meta);
		free(data);
		return tool_error(text);
	}
	if (data_len > total - received) {
		json_object_put(meta);
		free(data);
		return tool_error("chunk exceeds declared firmware size");
	}

	fd = open(image, O_WRONLY);
	if (fd < 0) {
		snprintf(text, sizeof(text), "failed to open firmware image: %s", strerror(errno));
		json_object_put(meta);
		free(data);
		return tool_error(text);
	}
	if (lseek(fd, (off_t)offset, SEEK_SET) < 0 || !write_all_fd(fd, data, data_len)) {
		snprintf(text, sizeof(text), "failed to write firmware chunk: %s", strerror(errno));
		close(fd);
		json_object_put(meta);
		free(data);
		return tool_error(text);
	}
	if (close(fd) < 0) {
		snprintf(text, sizeof(text), "failed to close firmware image: %s", strerror(errno));
		json_object_put(meta);
		free(data);
		return tool_error(text);
	}

	received += data_len;
	complete = received == total;
	json_object_object_add(meta, "received_bytes", json_object_new_int64((int64_t)received));
	json_object_object_add(meta, "complete", json_object_new_boolean(complete));
	json_object_object_add(meta, "validated", json_object_new_boolean(false));

	if (complete) {
		if (!sha256_file(image, actual_sha, cfg, err, sizeof(err))) {
			json_object_object_add(meta, "last_error", json_object_new_string(err));
			write_json_file(meta_path, meta);
			json_object_put(meta);
			free(data);
			return tool_error(err);
		}
		json_object_object_add(meta, "actual_sha256", json_object_new_string(actual_sha));
		if (strcmp(actual_sha, expected_sha)) {
			snprintf(text, sizeof(text), "firmware sha256 mismatch: expected %.64s got %.64s",
				 expected_sha, actual_sha);
			json_object_object_add(meta, "last_error", json_object_new_string(text));
			write_json_file(meta_path, meta);
			json_object_put(meta);
			free(data);
			return tool_error(text);
		}
	}

	if (!write_json_file(meta_path, meta)) {
		json_object_put(meta);
		free(data);
		return tool_error("failed to update firmware upload metadata");
	}

	structured = json_object_new_object();
	json_object_object_add(structured, "upload_id", json_object_new_string(upload_id));
	json_object_object_add(structured, "bytes_received", json_object_new_int64((int64_t)received));
	json_object_object_add(structured, "total_bytes", json_object_new_int64((int64_t)total));
	json_object_object_add(structured, "complete", json_object_new_boolean(complete));
	if (complete)
		json_object_object_add(structured, "sha256", json_object_new_string(expected_sha));
	snprintf(text, sizeof(text), "received %lu/%lu firmware bytes",
		 (unsigned long)received, (unsigned long)total);
	json_object_put(meta);
	free(data);
	return tool_result(text, structured, false);
}

static json_object *call_firmware_validate(json_object *args, struct mcpd_config *cfg)
{
	const char *upload_id, *expected_sha;
	size_t received, total, actual_size;
	char image[PATH_MAX], meta_path[PATH_MAX], log_path[PATH_MAX];
	char actual_sha[65], err[256], text[256];
	char *validate_argv[3];
	char *test_argv[5];
	struct proc_result validate_r, test_r;
	json_object *meta, *validation, *structured;
	bool keep_config, image_valid, forceable, allow_backup;
	int idx = 0;

	if (!json_get_string(args, "upload_id", &upload_id) || !valid_upload_id(upload_id))
		return tool_error("firmware_validate requires a safe upload_id");
	keep_config = json_get_bool_default(args, "keep_config", false);

	if (!firmware_paths(cfg, upload_id, image, sizeof(image), meta_path, sizeof(meta_path),
			    log_path, sizeof(log_path)))
		return tool_error("failed to build firmware upload paths");
	meta = read_json_file(meta_path);
	if (!meta)
		return tool_error("firmware upload metadata not found; call firmware_upload_begin first");
	if (!meta_get_size(meta, "received_bytes", &received) ||
	    !meta_get_size(meta, "total_bytes", &total)) {
		json_object_put(meta);
		return tool_error("firmware upload metadata is invalid");
	}
	expected_sha = meta_get_string(meta, "expected_sha256");
	if (received != total || !meta_get_bool(meta, "complete", false)) {
		json_object_put(meta);
		return tool_error("firmware upload is incomplete");
	}
	if (!file_size(image, &actual_size) || actual_size != total) {
		json_object_put(meta);
		return tool_error("firmware image size does not match upload metadata");
	}
	if (!sha256_file(image, actual_sha, cfg, err, sizeof(err))) {
		json_object_put(meta);
		return tool_error(err);
	}
	if (strcmp(actual_sha, expected_sha)) {
		snprintf(text, sizeof(text), "firmware sha256 mismatch: expected %.64s got %.64s",
			 expected_sha, actual_sha);
		json_object_put(meta);
		return tool_error(text);
	}

	validate_argv[0] = "/usr/libexec/validate_firmware_image";
	validate_argv[1] = image;
	validate_argv[2] = NULL;
	run_process(validate_argv, NULL, cfg->timeout_ms, cfg->max_output_bytes, &validate_r);
	validation = json_tokener_parse(validate_r.stdout_data ? validate_r.stdout_data : "");
	if (!validation || !json_object_is_type(validation, json_type_object)) {
		proc_result_free(&validate_r);
		if (validation)
			json_object_put(validation);
		json_object_put(meta);
		return tool_error("validate_firmware_image did not return JSON");
	}

	test_argv[idx++] = "/sbin/sysupgrade";
	test_argv[idx++] = "-T";
	if (!keep_config)
		test_argv[idx++] = "-n";
	test_argv[idx++] = image;
	test_argv[idx] = NULL;
	run_process(test_argv, NULL, cfg->timeout_ms, cfg->max_output_bytes, &test_r);

	image_valid = validation_bool(validation, "valid", false);
	forceable = validation_bool(validation, "forceable", false);
	allow_backup = validation_bool(validation, "allow_backup", false);

	json_object_object_add(meta, "actual_sha256", json_object_new_string(actual_sha));
	json_object_object_add(meta, "validated", json_object_new_boolean(true));
	json_object_object_add(meta, "validation_sha256", json_object_new_string(actual_sha));
	json_object_object_add(meta, "image_valid", json_object_new_boolean(image_valid));
	json_object_object_add(meta, "forceable", json_object_new_boolean(forceable));
	json_object_object_add(meta, "allow_backup", json_object_new_boolean(allow_backup));
	json_object_object_add(meta, "validated_keep_config", json_object_new_boolean(keep_config));
	json_object_object_add(meta, "validate_exit_code", json_object_new_int(validate_r.exit_code));
	json_object_object_add(meta, "validate_stderr",
			       json_object_new_string(validate_r.stderr_data ? validate_r.stderr_data : ""));
	json_object_object_add(meta, "sysupgrade_test_exit_code", json_object_new_int(test_r.exit_code));
	json_object_object_add(meta, "sysupgrade_test_stdout",
			       json_object_new_string(test_r.stdout_data ? test_r.stdout_data : ""));
	json_object_object_add(meta, "sysupgrade_test_stderr",
			       json_object_new_string(test_r.stderr_data ? test_r.stderr_data : ""));
	json_object_object_add(meta, "validation", json_object_get(validation));
	if (!write_json_file(meta_path, meta)) {
		proc_result_free(&validate_r);
		proc_result_free(&test_r);
		json_object_put(validation);
		json_object_put(meta);
		return tool_error("failed to update firmware validation metadata");
	}

	structured = json_object_new_object();
	json_object_object_add(structured, "upload_id", json_object_new_string(upload_id));
	json_object_object_add(structured, "sha256", json_object_new_string(actual_sha));
	json_object_object_add(structured, "valid", json_object_new_boolean(image_valid));
	json_object_object_add(structured, "forceable", json_object_new_boolean(forceable));
	json_object_object_add(structured, "allow_backup", json_object_new_boolean(allow_backup));
	json_object_object_add(structured, "keep_config", json_object_new_boolean(keep_config));
	json_object_object_add(structured, "validate", proc_structured(&validate_r));
	json_object_object_add(structured, "sysupgrade_test", proc_structured(&test_r));
	json_object_object_add(structured, "validation", json_object_get(validation));

	snprintf(text, sizeof(text),
		 "firmware validation complete: valid=%s forceable=%s allow_backup=%s sysupgrade_test_exit=%d",
		 image_valid ? "true" : "false", forceable ? "true" : "false",
		 allow_backup ? "true" : "false", test_r.exit_code);
	proc_result_free(&validate_r);
	proc_result_free(&test_r);
	json_object_put(validation);
	json_object_put(meta);
	return tool_result(text, structured, false);
}

static json_object *call_firmware_flash(json_object *args, struct mcpd_config *cfg)
{
	const char *upload_id, *expected_sha, *validation_sha;
	bool allow_reboot, keep_config, force;
	size_t received, total, actual_size;
	char image[PATH_MAX], meta_path[PATH_MAX], log_path[PATH_MAX];
	char actual_sha[65], err[256], text[256];
	json_object *meta, *structured, *command;
	bool image_valid, forceable, allow_backup;
	int test_exit;
	pid_t pid = -1;

	if (!json_get_string(args, "upload_id", &upload_id) || !valid_upload_id(upload_id))
		return tool_error("firmware_flash requires a safe upload_id");
	if (!json_get_bool_required(args, "allow_reboot", &allow_reboot) || !allow_reboot)
		return tool_error("firmware_flash requires allow_reboot: true");
	keep_config = json_get_bool_default(args, "keep_config", false);
	force = json_get_bool_default(args, "force", false);

	if (!firmware_paths(cfg, upload_id, image, sizeof(image), meta_path, sizeof(meta_path),
			    log_path, sizeof(log_path)))
		return tool_error("failed to build firmware upload paths");
	meta = read_json_file(meta_path);
	if (!meta)
		return tool_error("firmware upload metadata not found");
	if (!meta_get_size(meta, "received_bytes", &received) ||
	    !meta_get_size(meta, "total_bytes", &total)) {
		json_object_put(meta);
		return tool_error("firmware upload metadata is invalid");
	}
	expected_sha = meta_get_string(meta, "expected_sha256");
	if (received != total || !meta_get_bool(meta, "complete", false)) {
		json_object_put(meta);
		return tool_error("firmware upload is incomplete");
	}
	if (!meta_get_bool(meta, "validated", false)) {
		json_object_put(meta);
		return tool_error("firmware_flash requires prior firmware_validate");
	}
	if (!file_size(image, &actual_size) || actual_size != total) {
		json_object_put(meta);
		return tool_error("firmware image size does not match upload metadata");
	}
	if (!sha256_file(image, actual_sha, cfg, err, sizeof(err))) {
		json_object_put(meta);
		return tool_error(err);
	}
	if (strcmp(actual_sha, expected_sha)) {
		snprintf(text, sizeof(text), "firmware sha256 mismatch: expected %.64s got %.64s",
			 expected_sha, actual_sha);
		json_object_put(meta);
		return tool_error(text);
	}
	validation_sha = meta_get_string(meta, "validation_sha256");
	if (strcmp(actual_sha, validation_sha)) {
		json_object_put(meta);
		return tool_error("firmware image changed since validation");
	}

	image_valid = meta_get_bool(meta, "image_valid", false);
	forceable = meta_get_bool(meta, "forceable", false);
	allow_backup = meta_get_bool(meta, "allow_backup", false);
	test_exit = meta_get_int(meta, "sysupgrade_test_exit_code", 1);

	if (keep_config && !allow_backup) {
		json_object_put(meta);
		return tool_error("validated image is incompatible with keeping config");
	}
	if (force && !forceable) {
		json_object_put(meta);
		return tool_error("force requested but validation reported image is not forceable");
	}
	if (!force && (!image_valid || test_exit != 0)) {
		json_object_put(meta);
		return tool_error("validated image is not flashable without force");
	}
	if (!schedule_sysupgrade(image, log_path, keep_config, force, cfg->flash_delay_ms, &pid)) {
		snprintf(text, sizeof(text), "failed to schedule sysupgrade: %s", strerror(errno));
		json_object_put(meta);
		return tool_error(text);
	}

	json_object_object_add(meta, "flash_scheduled", json_object_new_boolean(true));
	json_object_object_add(meta, "flash_keep_config", json_object_new_boolean(keep_config));
	json_object_object_add(meta, "flash_force", json_object_new_boolean(force));
	json_object_object_add(meta, "flash_delay_ms", json_object_new_int((int)cfg->flash_delay_ms));
	write_json_file(meta_path, meta);

	command = json_object_new_array();
	json_object_array_add(command, json_object_new_string("/sbin/sysupgrade"));
	if (force)
		json_object_array_add(command, json_object_new_string("-F"));
	if (!keep_config)
		json_object_array_add(command, json_object_new_string("-n"));
	json_object_array_add(command, json_object_new_string(image));

	structured = json_object_new_object();
	json_object_object_add(structured, "upload_id", json_object_new_string(upload_id));
	json_object_object_add(structured, "scheduled", json_object_new_boolean(true));
	json_object_object_add(structured, "expected_disconnect", json_object_new_boolean(true));
	json_object_object_add(structured, "delay_ms", json_object_new_int((int)cfg->flash_delay_ms));
	json_object_object_add(structured, "keep_config", json_object_new_boolean(keep_config));
	json_object_object_add(structured, "force", json_object_new_boolean(force));
	json_object_object_add(structured, "log_path", json_object_new_string(log_path));
	json_object_object_add(structured, "command", command);
	json_object_object_add(structured, "scheduler_pid", json_object_new_int((int)pid));

	snprintf(text, sizeof(text), "scheduled sysupgrade in %u ms; MCP disconnect is expected",
		 cfg->flash_delay_ms);
	json_object_put(meta);
	return tool_result(text, structured, false);
}

static json_object *call_firmware_status(json_object *args, struct mcpd_config *cfg)
{
	const char *upload_id;
	size_t current_size = 0;
	char image[PATH_MAX], meta_path[PATH_MAX], log_path[PATH_MAX];
	char *tail;
	json_object *meta, *structured;
	char text[256];

	if (!json_get_string(args, "upload_id", &upload_id) || !valid_upload_id(upload_id))
		return tool_error("firmware_status requires a safe upload_id");
	if (!firmware_paths(cfg, upload_id, image, sizeof(image), meta_path, sizeof(meta_path),
			    log_path, sizeof(log_path)))
		return tool_error("failed to build firmware upload paths");

	meta = read_json_file(meta_path);
	structured = json_object_new_object();
	json_object_object_add(structured, "upload_id", json_object_new_string(upload_id));
	json_object_object_add(structured, "exists", json_object_new_boolean(meta != NULL));
	if (!meta) {
		snprintf(text, sizeof(text), "firmware upload %s not found", upload_id);
		return tool_result(text, structured, false);
	}

	file_size(image, &current_size);
	tail = file_tail(log_path, 4096);
	json_object_object_add(structured, "current_size", json_object_new_int64((int64_t)current_size));
	json_object_object_add(structured, "metadata", json_object_get(meta));
	json_object_object_add(structured, "log_tail", json_object_new_string(tail ? tail : ""));
	snprintf(text, sizeof(text), "firmware upload %s: %lu bytes, complete=%s, validated=%s, flash_scheduled=%s",
		 upload_id, (unsigned long)current_size,
		 meta_get_bool(meta, "complete", false) ? "true" : "false",
		 meta_get_bool(meta, "validated", false) ? "true" : "false",
		 meta_get_bool(meta, "flash_scheduled", false) ? "true" : "false");
	free(tail);
	json_object_put(meta);
	return tool_result(text, structured, false);
}

static json_object *handle_initialize(json_object *params)
{
	json_object *result = json_object_new_object();
	json_object *cap = json_object_new_object();
	json_object *tools = json_object_new_object();
	json_object *server = json_object_new_object();
	const char *protocol = MCPD_PROTOCOL_VERSION;

	if (params && json_object_is_type(params, json_type_object))
		json_get_string(params, "protocolVersion", &protocol);

	json_object_object_add(tools, "listChanged", json_object_new_boolean(false));
	json_object_object_add(cap, "tools", tools);
	json_object_object_add(server, "name", json_object_new_string(MCPD_SERVER_NAME));
	json_object_object_add(server, "version", json_object_new_string(MCPD_SERVER_VERSION));
	json_object_object_add(result, "protocolVersion", json_object_new_string(protocol));
	json_object_object_add(result, "capabilities", cap);
	json_object_object_add(result, "serverInfo", server);
	json_object_object_add(result, "instructions", json_object_new_string(board_instructions()));
	return result;
}

static json_object *handle_tools_list(void)
{
	json_object *result = json_object_new_object();
	json_object *tools = json_object_new_array();

	json_object_array_add(tools, new_tool("shell",
		"Run unrestricted /bin/sh -c commands and capture stdout/stderr/exit status.",
		tool_schema_shell()));
	json_object_array_add(tools, new_tool("write_file_base64",
		"Decode base64 and write, create, or append a file; optionally chmod it.",
		tool_schema_write_file()));
	json_object_array_add(tools, new_tool("ubus_call",
		"Execute an unrestricted ubus call with object, method, and JSON params.",
		tool_schema_ubus()));
	json_object_array_add(tools, new_tool("device_guide",
		"Return HugeIC development-board guidance as markdown.",
		tool_schema_device_guide()));
	json_object_array_add(tools, new_tool("firmware_upload_begin",
		"Create or reset a bounded sysupgrade firmware upload by upload_id, total size, and SHA256.",
		tool_schema_firmware_upload_begin()));
	json_object_array_add(tools, new_tool("firmware_upload_chunk",
		"Append a base64 firmware chunk at an exact byte offset and verify the final SHA256.",
		tool_schema_firmware_upload_chunk()));
	json_object_array_add(tools, new_tool("firmware_validate",
		"Validate a completed sysupgrade image on the board and store a hash-tied validation marker.",
		tool_schema_firmware_validate()));
	json_object_array_add(tools, new_tool("firmware_flash",
		"Schedule a delayed sysupgrade for a previously validated upload; requires allow_reboot: true.",
		tool_schema_firmware_flash()));
	json_object_array_add(tools, new_tool("firmware_status",
		"Report firmware upload, validation, and scheduled flash state for an upload_id.",
		tool_schema_firmware_status()));
	json_object_object_add(result, "tools", tools);
	return result;
}

static json_object *handle_tools_call(json_object *params, struct mcpd_config *cfg)
{
	const char *name;
	json_object *args = NULL;

	if (!params || !json_object_is_type(params, json_type_object))
		return tool_error("tools/call requires object params");
	if (!json_get_string(params, "name", &name) || !name[0])
		return tool_error("tools/call requires string param 'name'");
	if (!json_get_object(params, "arguments", &args))
		args = json_object_new_object();
	else
		json_object_get(args);

	json_object *ret;
	if (!strcmp(name, "shell"))
		ret = call_shell(args, cfg);
	else if (!strcmp(name, "write_file_base64"))
		ret = call_write_file(args);
	else if (!strcmp(name, "ubus_call"))
		ret = call_ubus(args, cfg);
	else if (!strcmp(name, "device_guide"))
		ret = call_device_guide(args);
	else if (!strcmp(name, "firmware_upload_begin"))
		ret = call_firmware_upload_begin(args, cfg);
	else if (!strcmp(name, "firmware_upload_chunk"))
		ret = call_firmware_upload_chunk(args, cfg);
	else if (!strcmp(name, "firmware_validate"))
		ret = call_firmware_validate(args, cfg);
	else if (!strcmp(name, "firmware_flash"))
		ret = call_firmware_flash(args, cfg);
	else if (!strcmp(name, "firmware_status"))
		ret = call_firmware_status(args, cfg);
	else
		ret = tool_error("unknown tool name");

	json_object_put(args);
	return ret;
}

static MCPD_MHD_RESULT handle_json_rpc(struct MHD_Connection *connection,
						json_object *req, struct mcpd_config *cfg)
{
	json_object *id = NULL, *params = NULL;
	const char *method;
	json_object *resp, *result;

	if (!json_object_is_type(req, json_type_object))
		return queue_json_object(connection, MHD_HTTP_OK,
					 jsonrpc_error(NULL, -32600, "Invalid Request"));

	json_object_object_get_ex(req, "id", &id);
	if (!json_get_string(req, "method", &method))
		return queue_json_object(connection, MHD_HTTP_OK,
					 jsonrpc_error(id, -32600, "Invalid Request"));
	json_object_object_get_ex(req, "params", &params);

	if (!strcmp(method, "notifications/initialized"))
		return queue_empty(connection, MHD_HTTP_ACCEPTED);

	if (!strcmp(method, "initialize"))
		result = handle_initialize(params);
	else if (!strcmp(method, "tools/list"))
		result = handle_tools_list();
	else if (!strcmp(method, "tools/call"))
		result = handle_tools_call(params, cfg);
	else if (!strcmp(method, "ping"))
		result = json_object_new_object();
	else {
		resp = jsonrpc_error(id, -32601, "Method not found");
		return queue_json_object(connection, MHD_HTTP_OK, resp);
	}

	resp = jsonrpc_response(id, result);
	return queue_json_object(connection, MHD_HTTP_OK, resp);
}

static MCPD_MHD_RESULT access_handler(void *cls, struct MHD_Connection *connection,
					      const char *url, const char *method,
					      const char *version, const char *upload_data,
					      size_t *upload_data_size, void **con_cls)
{
	struct mcpd_config *cfg = cls;
	struct request_ctx *ctx = *con_cls;
	json_object *req;

	(void)version;

	if (strcmp(method, MHD_HTTP_METHOD_POST) != 0)
		return queue_text(connection, MHD_HTTP_METHOD_NOT_ALLOWED,
				  "POST required\n", "text/plain");

	if (strcmp(url, cfg->endpoint) != 0)
		return queue_text(connection, MHD_HTTP_NOT_FOUND,
				  "not found\n", "text/plain");

	if (!ctx) {
		ctx = calloc(1, sizeof(*ctx));
		if (!ctx)
			return MHD_NO;
		*con_cls = ctx;
		return MHD_YES;
	}

	if (*upload_data_size) {
		if (!ctx->too_large && *upload_data_size <= cfg->max_request_bytes &&
		    ctx->len <= cfg->max_request_bytes - *upload_data_size) {
			char *p = realloc(ctx->body, ctx->len + *upload_data_size + 1);
			if (!p)
				return MHD_NO;
			ctx->body = p;
			memcpy(ctx->body + ctx->len, upload_data, *upload_data_size);
			ctx->len += *upload_data_size;
			ctx->body[ctx->len] = '\0';
		} else {
			ctx->too_large = true;
		}
		*upload_data_size = 0;
		return MHD_YES;
	}

	if (ctx->too_large)
		return queue_json_object(connection, MHD_HTTP_CONTENT_TOO_LARGE,
					 jsonrpc_error(NULL, -32600, "Request body too large"));

	if (!ctx->body)
		ctx->body = xstrdup("");
	req = json_tokener_parse(ctx->body ? ctx->body : "");
	if (!req)
		return queue_json_object(connection, MHD_HTTP_OK,
					 jsonrpc_error(NULL, -32700, "Parse error"));

	MCPD_MHD_RESULT ret = handle_json_rpc(connection, req, cfg);
	json_object_put(req);
	return ret;
}

static void request_completed(void *cls, struct MHD_Connection *connection,
				      void **con_cls, enum MHD_RequestTerminationCode toe)
{
	struct request_ctx *ctx = *con_cls;

	(void)cls;
	(void)connection;
	(void)toe;

	if (ctx) {
		free(ctx->body);
		free(ctx);
		*con_cls = NULL;
	}
}

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s [-p port] [-e endpoint] [-t timeout_ms] [-o max_output_bytes] [-r max_request_bytes] [-U upgrade_dir] [-M max_firmware_bytes] [-D flash_delay_ms]\n",
		prog);
}

static int parse_args(int argc, char **argv, struct mcpd_config *cfg)
{
	int opt;

	cfg->port = MCPD_DEFAULT_PORT;
	strncpy(cfg->endpoint, MCPD_DEFAULT_ENDPOINT, sizeof(cfg->endpoint) - 1);
	cfg->endpoint[sizeof(cfg->endpoint) - 1] = '\0';
	cfg->timeout_ms = MCPD_DEFAULT_TIMEOUT_MS;
	cfg->max_output_bytes = MCPD_DEFAULT_MAX_OUTPUT;
	cfg->max_request_bytes = MCPD_DEFAULT_MAX_REQUEST;
	strncpy(cfg->upgrade_dir, MCPD_DEFAULT_UPGRADE_DIR, sizeof(cfg->upgrade_dir) - 1);
	cfg->upgrade_dir[sizeof(cfg->upgrade_dir) - 1] = '\0';
	cfg->max_firmware_bytes = MCPD_DEFAULT_MAX_FIRMWARE;
	cfg->flash_delay_ms = MCPD_DEFAULT_FLASH_DELAY_MS;

	while ((opt = getopt(argc, argv, "p:e:t:o:r:U:M:D:h")) != -1) {
		char *end = NULL;
		unsigned long v;

		switch (opt) {
		case 'p':
			v = strtoul(optarg, &end, 10);
			if (!optarg[0] || *end || v == 0 || v > 65535)
				return -1;
			cfg->port = (unsigned int)v;
			break;
		case 'e':
			if (optarg[0] != '/' || strlen(optarg) >= sizeof(cfg->endpoint))
				return -1;
			strncpy(cfg->endpoint, optarg, sizeof(cfg->endpoint) - 1);
			cfg->endpoint[sizeof(cfg->endpoint) - 1] = '\0';
			break;
		case 't':
			v = strtoul(optarg, &end, 10);
			if (!optarg[0] || *end || v == 0)
				return -1;
			cfg->timeout_ms = (unsigned int)v;
			break;
		case 'o':
			v = strtoul(optarg, &end, 10);
			if (!optarg[0] || *end || v == 0)
				return -1;
			cfg->max_output_bytes = (size_t)v;
			break;
		case 'r':
			v = strtoul(optarg, &end, 10);
			if (!optarg[0] || *end || v == 0)
				return -1;
			cfg->max_request_bytes = (size_t)v;
			break;
		case 'U':
			if (optarg[0] != '/' || strlen(optarg) >= sizeof(cfg->upgrade_dir))
				return -1;
			strncpy(cfg->upgrade_dir, optarg, sizeof(cfg->upgrade_dir) - 1);
			cfg->upgrade_dir[sizeof(cfg->upgrade_dir) - 1] = '\0';
			break;
		case 'M':
			v = strtoul(optarg, &end, 10);
			if (!optarg[0] || *end || v == 0)
				return -1;
			cfg->max_firmware_bytes = (size_t)v;
			break;
		case 'D':
			v = strtoul(optarg, &end, 10);
			if (!optarg[0] || *end || v > 60000)
				return -1;
			cfg->flash_delay_ms = (unsigned int)v;
			break;
		case 'h':
		default:
			return -1;
		}
	}

	return 0;
}

int main(int argc, char **argv)
{
	struct mcpd_config cfg;
	struct MHD_Daemon *daemon;

	if (parse_args(argc, argv, &cfg) < 0) {
		usage(argv[0]);
		return 1;
	}

	signal(SIGTERM, signal_handler);
	signal(SIGINT, signal_handler);
	signal(SIGPIPE, SIG_IGN);

	daemon = MHD_start_daemon(MHD_USE_SELECT_INTERNALLY, cfg.port,
				  NULL, NULL, access_handler, &cfg,
				  MHD_OPTION_NOTIFY_COMPLETED, request_completed, NULL,
				  MHD_OPTION_END);
	if (!daemon) {
		fprintf(stderr, "failed to listen on port %u\n", cfg.port);
		return 1;
	}

	fprintf(stderr, "%s listening on 0.0.0.0:%u%s\n",
		MCPD_SERVER_NAME, cfg.port, cfg.endpoint);
	while (running)
		sleep(1);

	MHD_stop_daemon(daemon);
	return 0;
}
