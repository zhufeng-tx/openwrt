/* SPDX-License-Identifier: GPL-2.0-only */
#define _GNU_SOURCE
#include "../src/host/rt_host_auth.h"
#include "../src/host/rt_host_framing.h"
#include "../src/host/rt_host_secure.h"
#include "../src/host/rt_host_server.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <json-c/json.h>
#include <libubox/blobmsg.h>
#include <libubox/uloop.h>
#include <libubox/utils.h>
#include <openssl/evp.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
#ifdef __APPLE__
#include <util.h>
#else
#include <pty.h>
#endif

#define UART_JSON_MAX 8192U
#define UART_WIRE_MAX (UART_JSON_MAX + 64U)
#define IO_TIMEOUT_MS 1200
#define TEST_TIMEOUT_MS 4500

static const char request_id[] = "123e4567-e89b-42d3-a456-426614174000";

static int request_cb(void *context, const char *type, const char *request_id_value,
	uint8_t node_id, struct blob_attr *payload, struct blob_buf *result)
{
	(void)context;
	(void)request_id_value;
	(void)node_id;
	(void)payload;
	if (strcmp(type, "node.discover"))
		return -EINVAL;
	void *nodes = blobmsg_open_array(result, "nodes");
	void *node = blobmsg_open_table(result, NULL);
	blobmsg_add_u32(result, "nodeId", 1);
	blobmsg_add_string(result, "mac", "0011223344556677");
	blobmsg_close_table(result, node);
	blobmsg_close_array(result, nodes);
	return 0;
}

static void wait_for_io(int fd, short events)
{
	struct pollfd descriptor = { .fd = fd, .events = events };
	int result;
	do {
		result = poll(&descriptor, 1, IO_TIMEOUT_MS);
	} while (result < 0 && errno == EINTR);
	assert(result == 1 && (descriptor.revents & (events | POLLERR | POLLHUP)));
	assert(!(descriptor.revents & (POLLERR | POLLHUP)));
}

static void write_exact(int fd, const uint8_t *bytes, size_t length)
{
	while (length) {
		ssize_t count;
		wait_for_io(fd, POLLOUT);
		count = write(fd, bytes, length);
		if (count < 0 && errno == EINTR)
			continue;
		assert(count > 0);
		bytes += count;
		length -= (size_t)count;
	}
}

static void read_exact(int fd, uint8_t *bytes, size_t length)
{
	while (length) {
		ssize_t count;
		wait_for_io(fd, POLLIN);
		count = read(fd, bytes, length);
		if (count < 0 && errno == EINTR)
			continue;
		assert(count > 0);
		bytes += count;
		length -= (size_t)count;
	}
}

static void send_body(int master_fd, const uint8_t *body, size_t body_length)
{
	uint8_t wire[UART_WIRE_MAX];
	size_t wire_length;
	assert(rt_host_uart_encode(body, body_length, wire,
		sizeof(wire), &wire_length) == 0);
	assert(wire_length > 1 && wire[wire_length - 1] == 0);
	write_exact(master_fd, wire, wire_length);
}

static size_t receive_body(int master_fd, uint8_t body[UART_JSON_MAX + RT_HOST_SECURE_TRAILER_BYTES])
{
	uint8_t wire[UART_WIRE_MAX];
	size_t wire_length = 0, body_length = 0;
	for (;;) {
		read_exact(master_fd, &wire[wire_length], 1);
		if (wire[wire_length++] == 0)
			break;
		assert(wire_length < sizeof(wire));
	}
	assert(rt_host_uart_decode(wire, wire_length - 1U, body,
		UART_JSON_MAX + RT_HOST_SECURE_TRAILER_BYTES, &body_length) == 0);
	assert(body_length > 0 && body_length <= UART_JSON_MAX + RT_HOST_SECURE_TRAILER_BYTES);
	return body_length;
}

static struct json_object *parse_json(const uint8_t *json, size_t json_length)
{
	char text[UART_JSON_MAX + 1U];
	assert(json_length > 0 && json_length <= UART_JSON_MAX);
	memcpy(text, json, json_length);
	text[json_length] = '\0';
	struct json_object *object = json_tokener_parse(text);
	assert(object);
	return object;
}

static void send_plain_json(int master_fd, const char *json)
{
	send_body(master_fd, (const uint8_t *)json, strlen(json));
}

static void send_secure_json(int master_fd, const uint8_t session_key[32],
	uint64_t *sequence, const char *json)
{
	uint8_t body[UART_JSON_MAX + RT_HOST_SECURE_TRAILER_BYTES];
	size_t body_length;
	assert(*sequence < UINT64_MAX);
	assert(rt_host_secure_wrap(session_key, false, ++*sequence,
		(const uint8_t *)json, strlen(json), body, sizeof(body), &body_length) == 0);
	send_body(master_fd, body, body_length);
}

static struct json_object *receive_server_json(int master_fd,
	const uint8_t session_key[32], uint64_t *sequence)
{
	uint8_t body[UART_JSON_MAX + RT_HOST_SECURE_TRAILER_BYTES];
	uint8_t json[UART_JSON_MAX];
	size_t body_length = receive_body(master_fd, body), json_length = body_length;
	if (session_key) {
		assert(*sequence < UINT64_MAX);
		assert(rt_host_secure_unwrap(session_key, true, *sequence + 1U,
			body, body_length, json, sizeof(json), &json_length) == 0);
		(*sequence)++;
	} else {
		assert(body_length <= sizeof(json));
		memcpy(json, body, body_length);
	}
    return parse_json(json, json_length);
}

static struct json_object *receive_challenge_resync(int master_fd)
{
	for (unsigned attempt = 0; attempt < 8; attempt++) {
        uint8_t wire[UART_WIRE_MAX], body[UART_JSON_MAX + RT_HOST_SECURE_TRAILER_BYTES];
        size_t wire_length = 0, body_length = 0;
        for (;;) {
            read_exact(master_fd, &wire[wire_length], 1);
            if (wire[wire_length++] == 0) break;
            assert(wire_length < sizeof(wire));
        }
		if (wire_length == 1 || rt_host_uart_decode(wire, wire_length - 1,
		    body, sizeof(body), &body_length) || body_length > UART_JSON_MAX) {
			continue;
		}
        char text[UART_JSON_MAX + 1];
        memcpy(text, body, body_length);
        text[body_length] = '\0';
        struct json_object *reply = json_tokener_parse(text);
        if (!reply) continue;
        struct json_object *type, *identifier;
        bool is_challenge = json_object_object_get_ex(reply, "type", &type) &&
            json_object_object_get_ex(reply, "requestId", &identifier) &&
            !strcmp(json_object_get_string(type), "auth.challenge") &&
            !strcmp(json_object_get_string(identifier), request_id);
		if (is_challenge) return reply;
        json_object_put(reply);
    }
    assert(false && "no matching challenge after UART resynchronization");
    return NULL;
}

static const char *member_string(struct json_object *object, const char *name)
{
	struct json_object *field;
	assert(json_object_object_get_ex(object, name, &field));
	assert(json_object_is_type(field, json_type_string));
	return json_object_get_string(field);
}

static void proof_hex(const uint8_t proof[RT_HOST_PROOF_BYTES], char out[65])
{
	for (size_t i = 0; i < RT_HOST_PROOF_BYTES; i++)
		snprintf(out + i * 2U, 3, "%02x", proof[i]);
}

static void authenticate(int master_fd, const uint8_t key[32],
	const uint8_t client_nonce[32], uint8_t session_key[32],
	uint64_t *client_sequence, uint64_t *server_sequence, bool resynchronize)
{
	uint8_t server_nonce[RT_HOST_NONCE_BYTES], decoded_nonce[64];
	uint8_t expected[RT_HOST_PROOF_BYTES], actual[RT_HOST_PROOF_BYTES];
	char encoded_nonce[64], proof[65], text[512];
	struct json_object *reply, *payload;
	int decoded_length;
	assert(EVP_EncodeBlock((unsigned char *)encoded_nonce, client_nonce,
		(int)RT_HOST_NONCE_BYTES) == 44);
	snprintf(text, sizeof(text),
		"{\"version\":1,\"type\":\"auth.hello\",\"requestId\":\"%s\","
		"\"payload\":{\"clientNonce\":\"%s\"}}", request_id, encoded_nonce);
	send_plain_json(master_fd, text);
	reply = resynchronize ? receive_challenge_resync(master_fd) :
		receive_server_json(master_fd, NULL, server_sequence);
	assert(!strcmp(member_string(reply, "type"), "auth.challenge"));
	assert(json_object_object_get_ex(reply, "payload", &payload));
	const char *server_text = member_string(payload, "serverNonce");
	decoded_length = EVP_DecodeBlock(decoded_nonce,
		(const unsigned char *)server_text, (int)strlen(server_text));
	assert(decoded_length == 33 && server_text[strlen(server_text) - 1U] == '=');
	memcpy(server_nonce, decoded_nonce, sizeof(server_nonce));
	assert(rt_host_server_proof(key, client_nonce, server_nonce, expected) == 0);
	assert(strlen(member_string(payload, "serverProof")) == 64);
	for (size_t i = 0; i < sizeof(actual); i++) {
		unsigned int byte;
		assert(sscanf(member_string(payload, "serverProof") + i * 2U, "%2x", &byte) == 1);
		actual[i] = (uint8_t)byte;
	}
	assert(rt_host_proof_verify(expected, actual) == 0);
	json_object_put(reply);

	assert(rt_host_session_key(key, client_nonce, server_nonce, session_key) == 0);
	assert(rt_host_proof(key, client_nonce, server_nonce, expected) == 0);
	proof_hex(expected, proof);
	snprintf(text, sizeof(text),
		"{\"version\":1,\"type\":\"auth.proof\",\"requestId\":\"%s\","
		"\"payload\":{\"proof\":\"%s\"}}", request_id, proof);
	send_plain_json(master_fd, text);
	*client_sequence = 0;
	*server_sequence = 0;
	/* auth.ok is the final plaintext frame; subsequent frames are protected. */
	reply = receive_server_json(master_fd, NULL, server_sequence);
	assert(!strcmp(member_string(reply, "type"), "auth.ok"));
	json_object_put(reply);
	memset(expected, 0, sizeof(expected));
	memset(actual, 0, sizeof(actual));
}

static void discover(int master_fd, const uint8_t session_key[32],
	uint64_t *client_sequence, uint64_t *server_sequence)
{
	struct json_object *reply, *result, *nodes, *node;
	char text[256];
	snprintf(text, sizeof(text),
		"{\"version\":1,\"type\":\"node.discover\",\"requestId\":\"%s\"}",
		request_id);
	send_secure_json(master_fd, session_key, client_sequence, text);
	reply = receive_server_json(master_fd, session_key, server_sequence);
	assert(!strcmp(member_string(reply, "type"), "node.list"));
	assert(json_object_object_get_ex(reply, "result", &result));
	assert(json_object_object_get_ex(result, "nodes", &nodes));
	assert(json_object_array_length(nodes) == 1);
	node = json_object_array_get_idx(nodes, 0);
	struct json_object *node_id;
	assert(json_object_object_get_ex(node, "nodeId", &node_id));
	assert(json_object_get_int(node_id) == 1);
	assert(!strcmp(member_string(node, "mac"), "0011223344556677"));
	json_object_put(reply);
}

static int client_flow(int master_fd, int sync_write, int sync_read)
{
	uint8_t key[RT_HOST_KEY_BYTES], first_nonce[RT_HOST_NONCE_BYTES];
	uint8_t second_nonce[RT_HOST_NONCE_BYTES], first_session[RT_HOST_KEY_BYTES];
	uint8_t second_session[RT_HOST_KEY_BYTES];
	uint64_t client_sequence = 0, server_sequence = 0;
	for (size_t i = 0; i < sizeof(key); i++) {
		key[i] = (uint8_t)i;
		first_nonce[i] = (uint8_t)(0x40U + i);
		second_nonce[i] = (uint8_t)(0x60U + i);
	}
	authenticate(master_fd, key, first_nonce, first_session,
		&client_sequence, &server_sequence, false);
	assert(client_sequence == 0 && server_sequence == 0);
	discover(master_fd, first_session, &client_sequence, &server_sequence);
	assert(client_sequence == 1 && server_sequence == 1);

	/* Parent emits an unterminated old COBS output prefix before this hello. */
	uint8_t marker = '!';
	write_exact(sync_write, &marker, 1);
	read_exact(sync_read, &marker, 1);
	/* A plaintext hello resets the session and emits a delimiter for the old prefix. */
	authenticate(master_fd, key, second_nonce, second_session,
		&client_sequence, &server_sequence, true);
	assert(client_sequence == 0 && server_sequence == 0);
	assert(memcmp(first_session, second_session, sizeof(first_session)) != 0);
	discover(master_fd, second_session, &client_sequence, &server_sequence);
	assert(client_sequence == 1 && server_sequence == 1);
	memset(first_session, 0, sizeof(first_session));
	memset(second_session, 0, sizeof(second_session));
	return 0;
}

struct child_watch {
	struct uloop_process process;
	bool done;
	bool passed;
	bool timed_out;
};

struct timeout_watch {
	struct uloop_timeout timer;
	struct child_watch *child;
};

struct sync_watch {
	struct uloop_fd watcher;
	struct rt_host_server *server;
	int reply_fd;
	bool done;
};

static void sync_cb(struct uloop_fd *watcher, unsigned int events)
{
	struct sync_watch *sync = container_of(watcher, struct sync_watch, watcher);
	static const uint8_t old_prefix[] = {3, 'X', 'Y'};
	uint8_t marker;
	(void)events;
	if (sync->done) return;
	read_exact(watcher->fd, &marker, 1);
	assert(marker == '!');
	assert(rt_host_server_test_emit_uart_prefix(sync->server,
		old_prefix, sizeof(old_prefix)) == 0);
	marker = '!';
	write_exact(sync->reply_fd, &marker, 1);
	sync->done = true;
	uloop_fd_delete(watcher);
}

static void child_exit(struct uloop_process *process, int status)
{
	struct child_watch *child = container_of(process, struct child_watch, process);
	child->done = true;
	child->passed = WIFEXITED(status) && WEXITSTATUS(status) == 0;
	uloop_end();
}

static void timeout_cb(struct uloop_timeout *timer)
{
	struct timeout_watch *watch = container_of(timer, struct timeout_watch, timer);
	if (!watch->child->done) {
		watch->child->timed_out = true;
		(void)kill(watch->child->process.pid, SIGKILL);
	}
	uloop_end();
}

int main(void)
{
	struct rt_host_server *server;
	struct child_watch child = { .process.cb = child_exit };
	struct timeout_watch timeout = { .timer.cb = timeout_cb, .child = &child };
	char slave_path[128];
	int master_fd, slave_fd;
	int notify_pipe[2], reply_pipe[2];
	struct sync_watch sync = { .watcher.cb = sync_cb };
	uint16_t port;
	assert(openpty(&master_fd, &slave_fd, slave_path, NULL, NULL) == 0);
	assert(pipe(notify_pipe) == 0 && pipe(reply_pipe) == 0);
	assert(uloop_init() == 0);
	server = NULL;
	port = (uint16_t)(40000U + (unsigned)getpid() % 20000U);
	for (unsigned i = 0; i < 100U && !server; i++)
		server = rt_host_server_start(++port, slave_path, "test", request_cb, NULL);
	assert(server);
	close(slave_fd);
	sync.watcher.fd = notify_pipe[0];
	sync.server = server;
	sync.reply_fd = reply_pipe[1];
	child.process.pid = fork();
	assert(child.process.pid >= 0);
	if (child.process.pid == 0) {
		int result;
		close(slave_fd);
		close(notify_pipe[0]);
		close(reply_pipe[1]);
		result = client_flow(master_fd, notify_pipe[1], reply_pipe[0]);
		close(master_fd);
		_exit(result);
	}
	close(master_fd);
	close(notify_pipe[1]);
	close(reply_pipe[0]);
	assert(uloop_fd_add(&sync.watcher, ULOOP_READ) == 0);
	assert(uloop_process_add(&child.process) == 0);
	uloop_timeout_set(&timeout.timer, TEST_TIMEOUT_MS);
	uloop_run();
	uloop_timeout_cancel(&timeout.timer);
	if (child.timed_out)
		(void)waitpid(child.process.pid, NULL, 0);
	if (sync.watcher.registered) uloop_fd_delete(&sync.watcher);
	close(notify_pipe[0]);
	close(reply_pipe[1]);
	assert(child.done && child.passed && !child.timed_out);
	rt_host_server_stop(server);
	uloop_done();
	return 0;
}
