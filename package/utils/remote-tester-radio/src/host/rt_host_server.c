/* SPDX-License-Identifier: GPL-2.0-only */
#define _GNU_SOURCE
#include "rt_host_server.h"
#include "rt_host_auth.h"
#include "rt_host_framing.h"
#include "rt_host_secure.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>
#include <libubox/uloop.h>
#include <libubox/utils.h>
#include <mbedtls/base64.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <termios.h>
#include <unistd.h>

#define HOST_JSON_MAX 8192U
#define HOST_INPUT_MAX (HOST_JSON_MAX + 64U)
#define HOST_OUTPUT_MAX (64U * 1024U)

enum host_field { HOST_VERSION, HOST_TYPE, HOST_REQUEST_ID, HOST_NODE_ID, HOST_PAYLOAD, __HOST_FIELD_MAX };
enum nonce_field { NONCE_VALUE, __NONCE_FIELD_MAX };
enum proof_field { PROOF_VALUE, __PROOF_FIELD_MAX };

static const struct blobmsg_policy host_policy[__HOST_FIELD_MAX] = {
    [HOST_VERSION] = { .name = "version", .type = BLOBMSG_TYPE_INT32 },
    [HOST_TYPE] = { .name = "type", .type = BLOBMSG_TYPE_STRING },
    [HOST_REQUEST_ID] = { .name = "requestId", .type = BLOBMSG_TYPE_STRING },
    [HOST_NODE_ID] = { .name = "nodeId", .type = BLOBMSG_TYPE_INT32 },
    [HOST_PAYLOAD] = { .name = "payload", .type = BLOBMSG_TYPE_TABLE },
};
static const struct blobmsg_policy nonce_policy[__NONCE_FIELD_MAX] = {
    [NONCE_VALUE] = { .name = "clientNonce", .type = BLOBMSG_TYPE_STRING },
};
static const struct blobmsg_policy proof_policy[__PROOF_FIELD_MAX] = {
    [PROOF_VALUE] = { .name = "proof", .type = BLOBMSG_TYPE_STRING },
};

struct rt_host_server;
struct host_peer {
    struct uloop_fd watcher;
    struct uloop_timeout auth_timeout;
    struct rt_host_server *server;
    bool uart;
    bool authenticated;
    bool challenge_pending;
    bool subscribed;
    bool writer;
    bool close_after_write;
    bool discard_input;
    uint8_t client_nonce[RT_HOST_NONCE_BYTES];
    uint8_t server_nonce[RT_HOST_NONCE_BYTES];
    uint8_t session_key[RT_HOST_KEY_BYTES];
    uint64_t tx_sequence;
    uint64_t rx_sequence;
    uint8_t input[HOST_INPUT_MAX];
    size_t input_used;
    uint8_t output[HOST_OUTPUT_MAX];
    size_t output_used;
};

struct rt_host_server {
    struct uloop_fd listener;
    struct host_peer tcp;
    struct host_peer uart;
    uint8_t key[RT_HOST_KEY_BYTES];
    rt_host_request_cb callback;
    void *context;
};

static int peer_watch(struct host_peer *peer);

static int open_tcp_socket(void)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    int flags;
    if (fd < 0) return -1;
    flags = fcntl(fd, F_GETFL);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) ||
        fcntl(fd, F_SETFD, FD_CLOEXEC)) {
        int saved = errno;
        close(fd);
        errno = saved;
        return -1;
    }
    return fd;
}

static void peer_close(struct host_peer *peer)
{
    bool was_writer = peer->writer;
    struct host_peer *other = peer->uart ? &peer->server->tcp : &peer->server->uart;
    uloop_timeout_cancel(&peer->auth_timeout);
    if (peer->watcher.fd >= 0) {
        uloop_fd_delete(&peer->watcher);
        close(peer->watcher.fd);
    }
    peer->watcher.fd = -1;
    peer->authenticated = false;
    peer->challenge_pending = false;
    peer->subscribed = false;
    peer->writer = false;
    peer->input_used = 0;
    peer->output_used = 0;
    memset(peer->client_nonce, 0, sizeof(peer->client_nonce));
    memset(peer->server_nonce, 0, sizeof(peer->server_nonce));
    memset(peer->session_key, 0, sizeof(peer->session_key));
    peer->tx_sequence = peer->rx_sequence = 0;
    if (was_writer && other->watcher.fd >= 0 && other->authenticated)
        other->writer = true;
}

static void peer_reset_uart_session(struct host_peer *peer)
{
    if (peer->writer && peer->server->tcp.watcher.fd >= 0 &&
        peer->server->tcp.authenticated)
        peer->server->tcp.writer = true;
    uloop_timeout_cancel(&peer->auth_timeout);
    peer->authenticated = false;
    peer->challenge_pending = false;
    peer->subscribed = false;
    peer->writer = false;
    peer->close_after_write = false;
    /* A prior COBS frame may have been only partly written. Terminate it
     * before queuing the next plain challenge so the peer can resynchronize. */
    peer->output[0] = 0;
    peer->output_used = 1;
    peer->tx_sequence = peer->rx_sequence = 0;
    memset(peer->client_nonce, 0, sizeof(peer->client_nonce));
    memset(peer->server_nonce, 0, sizeof(peer->server_nonce));
    memset(peer->session_key, 0, sizeof(peer->session_key));
    (void)peer_watch(peer);
}

static int peer_watch(struct host_peer *peer)
{
    return uloop_fd_add(&peer->watcher,
        ULOOP_READ | (peer->output_used ? ULOOP_WRITE : 0));
}

static int peer_queue_json(struct host_peer *peer, const char *json)
{
    size_t length = strlen(json), body_length = length, wire_length;
    uint8_t secured[HOST_JSON_MAX + RT_HOST_SECURE_TRAILER_BYTES];
    const uint8_t *body = (const uint8_t *)json;
    uint8_t header[4];
    int error;
    if (length == 0 || length > HOST_JSON_MAX) return -EMSGSIZE;
    if (peer->authenticated) {
        if (peer->tx_sequence == UINT64_MAX) return -EOVERFLOW;
        error = rt_host_secure_wrap(peer->session_key, true,
            peer->tx_sequence + 1, body, length,
            secured, sizeof(secured), &body_length);
        if (error) return error;
        body = secured;
    }
    if (peer->uart) {
        uint8_t wire[HOST_INPUT_MAX];
        error = rt_host_uart_encode(body, body_length,
            wire, sizeof(wire), &wire_length);
        if (error) return error;
        if (wire_length > sizeof(peer->output) - peer->output_used) return -ENOSPC;
        memcpy(peer->output + peer->output_used, wire, wire_length);
    } else {
        error = rt_host_tcp_header(body_length, header);
        if (error) return error;
        wire_length = body_length + sizeof(header);
        if (wire_length > sizeof(peer->output) - peer->output_used) return -ENOSPC;
        memcpy(peer->output + peer->output_used, header, sizeof(header));
        memcpy(peer->output + peer->output_used + sizeof(header), body, body_length);
    }
    peer->output_used += wire_length;
    if (peer->authenticated) peer->tx_sequence++;
    return peer_watch(peer);
}

static int peer_send_blob(struct host_peer *peer, struct blob_buf *buffer)
{
    char *json = blobmsg_format_json(buffer->head, true);
    int result;
    if (!json) return -ENOMEM;
    result = peer_queue_json(peer, json);
    free(json);
    return result;
}

static int peer_reply(struct host_peer *peer, const char *type,
    const char *request_id, const char *error, struct blob_buf *result)
{
    struct blob_buf response = {};
    void *table;
    int status;
    blob_buf_init(&response, 0);
    blobmsg_add_u32(&response, "version", 1);
    blobmsg_add_string(&response, "type", type);
    if (request_id) blobmsg_add_string(&response, "requestId", request_id);
    if (error) {
        const char *code = !strcmp(error, "authentication_failed") ||
            !strcmp(error, "not_permitted") || !strcmp(error, "unknown_request") ?
            error : "request_failed";
        void *error_table = blobmsg_open_table(&response, "error");
        blobmsg_add_string(&response, "code", code);
        blobmsg_add_string(&response, "message", error);
        blobmsg_close_table(&response, error_table);
    }
    if (result) {
        struct blob_attr *attr;
        size_t remaining;
        table = blobmsg_open_table(&response,
            !strcmp(type, "auth.challenge") ? "payload" : "result");
        blobmsg_for_each_attr(attr, result->head, remaining)
            blobmsg_add_blob(&response, attr);
        blobmsg_close_table(&response, table);
    }
    status = peer_send_blob(peer, &response);
    blob_buf_free(&response);
    return status;
}

static int decode_hex_proof(const char *hex, uint8_t proof[RT_HOST_PROOF_BYTES])
{
    if (strlen(hex) != RT_HOST_PROOF_BYTES * 2) return -EINVAL;
    for (size_t i = 0; i < RT_HOST_PROOF_BYTES; i++) {
        int high, low;
        char a = hex[i * 2], b = hex[i * 2 + 1];
        high = a >= '0' && a <= '9' ? a - '0' : a >= 'a' && a <= 'f' ? a - 'a' + 10 : -1;
        low = b >= '0' && b <= '9' ? b - '0' : b >= 'a' && b <= 'f' ? b - 'a' + 10 : -1;
        if (high < 0 || low < 0) return -EINVAL;
        proof[i] = (uint8_t)((high << 4) | low);
    }
    return 0;
}

static int peer_auth_hello(struct host_peer *peer, const char *request_id,
    struct blob_attr *payload)
{
    struct blob_attr *fields[__NONCE_FIELD_MAX];
    struct blob_buf result = {};
    unsigned char encoded[64];
    uint8_t server_proof[RT_HOST_PROOF_BYTES];
    char proof_hex[RT_HOST_PROOF_BYTES * 2 + 1];
    size_t decoded_length, encoded_length;
    int error;
    if (!payload || !request_id) return -EINVAL;
    blobmsg_parse(nonce_policy, __NONCE_FIELD_MAX, fields,
        blobmsg_data(payload), blobmsg_len(payload));
    if (!fields[NONCE_VALUE]) return -EINVAL;
    error = mbedtls_base64_decode(peer->client_nonce, sizeof(peer->client_nonce),
        &decoded_length, (const unsigned char *)blobmsg_get_string(fields[NONCE_VALUE]),
        strlen(blobmsg_get_string(fields[NONCE_VALUE])));
    if (error || decoded_length != RT_HOST_NONCE_BYTES) return -EINVAL;
    error = rt_host_random_nonce(peer->server_nonce);
    if (error) return error;
    error = mbedtls_base64_encode(encoded, sizeof(encoded), &encoded_length,
        peer->server_nonce, sizeof(peer->server_nonce));
    if (error || encoded_length >= sizeof(encoded)) return -EIO;
    encoded[encoded_length] = '\0';
    error = rt_host_server_proof(peer->server->key, peer->client_nonce,
        peer->server_nonce, server_proof);
    if (error) return error;
    for (size_t i = 0; i < RT_HOST_PROOF_BYTES; i++)
        snprintf(proof_hex + i * 2, 3, "%02x", server_proof[i]);
    memset(server_proof, 0, sizeof(server_proof));
    blob_buf_init(&result, 0);
    blobmsg_add_string(&result, "serverNonce", (const char *)encoded);
    blobmsg_add_string(&result, "serverProof", proof_hex);
    error = peer_reply(peer, "auth.challenge", request_id, NULL, &result);
    blob_buf_free(&result);
    peer->challenge_pending = error == 0;
    if (!error) uloop_timeout_set(&peer->auth_timeout, 5000);
    return error;
}

static int peer_auth_proof(struct host_peer *peer, const char *request_id,
    struct blob_attr *payload)
{
    struct blob_attr *fields[__PROOF_FIELD_MAX];
    uint8_t expected[RT_HOST_PROOF_BYTES], actual[RT_HOST_PROOF_BYTES];
    int error;
    if (!payload || !request_id || !peer->challenge_pending) return -EINVAL;
    blobmsg_parse(proof_policy, __PROOF_FIELD_MAX, fields,
        blobmsg_data(payload), blobmsg_len(payload));
    if (!fields[PROOF_VALUE]) return -EINVAL;
    error = decode_hex_proof(blobmsg_get_string(fields[PROOF_VALUE]), actual);
    if (error) return error;
    error = rt_host_proof(peer->server->key, peer->client_nonce,
        peer->server_nonce, expected);
    if (!error) error = rt_host_proof_verify(expected, actual);
    memset(expected, 0, sizeof(expected));
    memset(actual, 0, sizeof(actual));
    peer->challenge_pending = false;
    if (error) return error;
    error = rt_host_session_key(peer->server->key, peer->client_nonce,
        peer->server_nonce, peer->session_key);
    if (error) return error;
    /* auth.ok is the final plain handshake frame; protected frames follow it. */
    error = peer_reply(peer, "auth.ok", request_id, NULL, NULL);
    if (error) { memset(peer->session_key, 0, sizeof(peer->session_key)); return error; }
    peer->authenticated = true;
    uloop_timeout_cancel(&peer->auth_timeout);
    peer->server->tcp.writer = false;
    peer->server->uart.writer = false;
    peer->writer = true;
    return 0;
}

static bool valid_request_id(const char *request_id)
{
    static const size_t dash_positions[] = {8, 13, 18, 23};
    if (!request_id || strlen(request_id) != 36) return false;
    for (size_t i = 0; i < 36; i++) {
        bool dash = false;
        for (size_t j = 0; j < 4; j++) dash |= dash_positions[j] == i;
        if (dash ? request_id[i] != '-' :
            !((request_id[i] >= '0' && request_id[i] <= '9') ||
              (request_id[i] >= 'a' && request_id[i] <= 'f')))
            return false;
    }
    return true;
}

static void peer_handle_json(struct host_peer *peer, const uint8_t *bytes, size_t length)
{
    struct blob_attr *fields[__HOST_FIELD_MAX];
    struct blob_buf request = {}, result = {};
    char json[HOST_JSON_MAX + 1];
    const char *type, *request_id;
    uint32_t node_id = 0;
    int error;

    if (length == 0 || length > HOST_JSON_MAX) return;
    memcpy(json, bytes, length);
    json[length] = '\0';
    blob_buf_init(&request, 0);
    if (!blobmsg_add_json_from_string(&request, json)) goto out;
    memset(fields, 0, sizeof(fields));
    blobmsg_parse(host_policy, __HOST_FIELD_MAX, fields,
        blobmsg_data(request.head), blobmsg_len(request.head));
    if (!fields[HOST_VERSION] || blobmsg_get_u32(fields[HOST_VERSION]) != 1 ||
        !fields[HOST_TYPE]) goto out;
    type = blobmsg_get_string(fields[HOST_TYPE]);
    request_id = fields[HOST_REQUEST_ID] ? blobmsg_get_string(fields[HOST_REQUEST_ID]) : NULL;
    if (!valid_request_id(request_id)) goto out;
    if (fields[HOST_NODE_ID]) node_id = blobmsg_get_u32(fields[HOST_NODE_ID]);

    if (!peer->authenticated) {
        if (!strcmp(type, "auth.hello"))
            error = peer_auth_hello(peer, request_id, fields[HOST_PAYLOAD]);
        else if (!strcmp(type, "auth.proof"))
            error = peer_auth_proof(peer, request_id, fields[HOST_PAYLOAD]);
        else error = -EACCES;
        if (error) {
            (void)peer_reply(peer, "auth.error", request_id,
                "authentication_failed", NULL);
            peer->close_after_write = true;
        }
        goto out;
    }
    if (!strcmp(type, "auth.logout")) {
        if (peer->uart) peer_reset_uart_session(peer);
        else peer_close(peer);
        goto out;
    }
    if (!strcmp(type, "node.subscribe")) {
        peer->subscribed = true;
        (void)peer_reply(peer, "node.subscribed", request_id, NULL, NULL);
        goto out;
    }
    bool discover = !strcmp(type, "node.discover");
    bool status = !strcmp(type, "node.status");
    if ((!discover && (node_id == 0 || node_id > 8)) ||
        (!discover && !status && !peer->writer)) {
        (void)peer_reply(peer, "request.error", request_id, "not_permitted", NULL);
        goto out;
    }
    if (!discover && !status && strcmp(type, "serial.write") &&
        strcmp(type, "iperf.start") && strcmp(type, "iperf.stop")) {
        (void)peer_reply(peer, "request.error", request_id, "unknown_request", NULL);
        goto out;
    }
    blob_buf_init(&result, 0);
    error = peer->server->callback ? peer->server->callback(peer->server->context,
        type, request_id, (uint8_t)node_id, fields[HOST_PAYLOAD], &result) : -ENOSYS;
    (void)peer_reply(peer,
        discover ? "node.list" : status ? "node.status.result" :
        !strcmp(type, "serial.write") ? "serial.write.result" : "iperf.result",
        request_id, error ? strerror(-error) : NULL, &result);
    blob_buf_free(&result);
out:
    blob_buf_free(&request);
}

static bool plain_uart_hello(const uint8_t *body, size_t length)
{
    struct blob_buf request = {};
    struct blob_attr *fields[__HOST_FIELD_MAX];
    char json[HOST_JSON_MAX + 1];
    bool hello = false;
    if (length == 0 || length > HOST_JSON_MAX) return false;
    memcpy(json, body, length);
    json[length] = '\0';
    blob_buf_init(&request, 0);
    if (blobmsg_add_json_from_string(&request, json)) {
        memset(fields, 0, sizeof(fields));
        blobmsg_parse(host_policy, __HOST_FIELD_MAX, fields,
            blobmsg_data(request.head), blobmsg_len(request.head));
        hello = fields[HOST_TYPE] &&
            !strcmp(blobmsg_get_string(fields[HOST_TYPE]), "auth.hello");
    }
    blob_buf_free(&request);
    return hello;
}

static void peer_handle_body(struct host_peer *peer, const uint8_t *body, size_t length)
{
    uint8_t json[HOST_JSON_MAX];
    size_t json_length = length;
    if (peer->authenticated && peer->uart && plain_uart_hello(body, length)) {
        peer_reset_uart_session(peer);
        peer_handle_json(peer, body, length);
        return;
    }
    if (peer->authenticated) {
        if (peer->rx_sequence == UINT64_MAX ||
            rt_host_secure_unwrap(peer->session_key, false,
                peer->rx_sequence + 1, body, length,
                json, sizeof(json), &json_length)) {
            if (peer->uart) peer_reset_uart_session(peer);
            else peer_close(peer);
            return;
        }
        peer->rx_sequence++;
        peer_handle_json(peer, json, json_length);
    } else {
        peer_handle_json(peer, body, length);
    }
}

static void peer_flush(struct host_peer *peer)
{
    while (peer->output_used) {
        ssize_t count = write(peer->watcher.fd, peer->output, peer->output_used);
        if (count < 0 && errno == EINTR) continue;
        if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) break;
        if (count <= 0) { peer_close(peer); return; }
        peer->output_used -= (size_t)count;
        memmove(peer->output, peer->output + count, peer->output_used);
    }
    if (!peer->output_used && peer->close_after_write) {
        if (!peer->uart) { peer_close(peer); return; }
        peer_reset_uart_session(peer);
    }
    (void)peer_watch(peer);
}

static void peer_parse_input(struct host_peer *peer)
{
    if (peer->uart) {
        size_t consumed = 0;
        for (size_t i = 0; i < peer->input_used; i++) {
            if (peer->input[i] != 0) continue;
            if (!peer->discard_input && i > consumed) {
                uint8_t body[HOST_INPUT_MAX];
                size_t body_len;
                if (!rt_host_uart_decode(peer->input + consumed, i - consumed,
                    body, sizeof(body), &body_len))
                    peer_handle_body(peer, body, body_len);
            }
            consumed = i + 1;
            peer->discard_input = false;
        }
        if (consumed) {
            peer->input_used -= consumed;
            memmove(peer->input, peer->input + consumed, peer->input_used);
        }
    } else {
        while (peer->input_used >= 4) {
            uint32_t length = rt_host_tcp_length(peer->input);
            if (length == 0 || length > HOST_JSON_MAX + RT_HOST_SECURE_TRAILER_BYTES) {
                peer_close(peer); return;
            }
            if (peer->input_used < 4U + length) break;
            peer_handle_body(peer, peer->input + 4, length);
            if (peer->watcher.fd < 0) return;
            peer->input_used -= 4U + length;
            memmove(peer->input, peer->input + 4U + length, peer->input_used);
        }
    }
}

static void peer_cb(struct uloop_fd *watcher, unsigned int events)
{
    struct host_peer *peer = container_of(watcher, struct host_peer, watcher);
    if (events & ULOOP_READ) {
        while (peer->watcher.fd >= 0) {
            ssize_t count = read(peer->watcher.fd,
                peer->input + peer->input_used, sizeof(peer->input) - peer->input_used);
            if (count < 0 && errno == EINTR) continue;
            if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) break;
            if (count <= 0) { peer_close(peer); return; }
            peer->input_used += (size_t)count;
            peer_parse_input(peer);
            if (peer->watcher.fd < 0) return;
            if (peer->input_used == sizeof(peer->input)) {
                if (!peer->uart) { peer_close(peer); return; }
                peer->input_used = 0;
                peer->discard_input = true;
            }
        }
    }
    if ((events & ULOOP_WRITE) && peer->watcher.fd >= 0) peer_flush(peer);
}

static void auth_timeout_cb(struct uloop_timeout *timeout)
{
    struct host_peer *peer = container_of(timeout, struct host_peer, auth_timeout);
    if (!peer->authenticated) {
        if (peer->uart) peer_reset_uart_session(peer);
        else peer_close(peer);
    }
}

static void listener_cb(struct uloop_fd *watcher, unsigned int events)
{
    struct rt_host_server *server = container_of(watcher, struct rt_host_server, listener);
    int fd, flags;
    (void)events;
    for (;;) {
        fd = accept(watcher->fd, NULL, NULL);
        if (fd < 0 && errno == EINTR) continue;
        if (fd < 0) return;
        if (server->tcp.watcher.fd >= 0) { close(fd); continue; }
        flags = fcntl(fd, F_GETFL);
        if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) { close(fd); continue; }
        server->tcp.watcher.fd = fd;
        server->tcp.close_after_write = false;
        server->tcp.discard_input = false;
        (void)peer_watch(&server->tcp);
        uloop_timeout_set(&server->tcp.auth_timeout, 5000);
    }
}

static int open_uart(const char *path)
{
    struct termios term;
    int fd = open(path, O_RDWR | O_NOCTTY | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) return -errno;
    if (tcgetattr(fd, &term)) { int error = -errno; close(fd); return error; }
    cfmakeraw(&term);
    term.c_cflag |= CLOCAL | CREAD;
    if (cfsetispeed(&term, B115200) || cfsetospeed(&term, B115200) ||
        tcsetattr(fd, TCSANOW, &term)) {
        int error = -errno;
        close(fd);
        return error;
    }
    return fd;
}

struct rt_host_server *rt_host_server_start(uint16_t tcp_port,
    const char *uart_device, const char *key_file,
    rt_host_request_cb callback, void *context)
{
    struct rt_host_server *server = calloc(1, sizeof(*server));
    struct sockaddr_in address = { .sin_family = AF_INET, .sin_addr.s_addr = INADDR_ANY };
    int fd, enabled = 1, error;
    if (!server) return NULL;
    if (!key_file || tcp_port == 0) { free(server); errno = EINVAL; return NULL; }
    server->listener.fd = server->tcp.watcher.fd = server->uart.watcher.fd = -1;
    server->listener.cb = listener_cb;
    server->tcp.watcher.cb = server->uart.watcher.cb = peer_cb;
    server->tcp.auth_timeout.cb = server->uart.auth_timeout.cb = auth_timeout_cb;
    server->tcp.server = server->uart.server = server;
    server->uart.uart = true;
    server->callback = callback;
    server->context = context;
    error = rt_host_key_load(key_file, server->key);
    if (error) { errno = -error; goto fail; }
    fd = open_tcp_socket();
    if (fd < 0) goto fail;
    (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof(enabled));
    address.sin_port = htons(tcp_port);
    if (bind(fd, (struct sockaddr *)&address, sizeof(address)) || listen(fd, 2)) {
        int saved = errno;
        close(fd);
        errno = saved;
        goto fail;
    }
    server->listener.fd = fd;
    if (uloop_fd_add(&server->listener, ULOOP_READ)) goto fail;
    if (uart_device && uart_device[0]) {
        fd = open_uart(uart_device);
        if (fd >= 0) {
            server->uart.watcher.fd = fd;
            if (peer_watch(&server->uart)) peer_close(&server->uart);
        }
    }
    return server;
fail:
    error = errno;
    rt_host_server_stop(server);
    errno = error;
    return NULL;
}

void rt_host_server_stop(struct rt_host_server *server)
{
    if (!server) return;
    peer_close(&server->tcp);
    peer_close(&server->uart);
    if (server->listener.fd >= 0) {
        uloop_fd_delete(&server->listener);
        close(server->listener.fd);
    }
    memset(server->key, 0, sizeof(server->key));
    free(server);
}

int rt_host_server_publish(struct rt_host_server *server, const char *json)
{
    int delivered = 0, error = -ENOTCONN;
    if (!server || !json) return -EINVAL;
    if (server->tcp.watcher.fd >= 0 && server->tcp.authenticated && server->tcp.subscribed) {
        error = peer_queue_json(&server->tcp, json);
        if (!error) delivered++;
    }
    if (server->uart.watcher.fd >= 0 && server->uart.authenticated && server->uart.subscribed) {
        error = peer_queue_json(&server->uart, json);
        if (!error) delivered++;
    }
    return delivered ? 0 : error;
}

bool rt_host_server_has_subscriber(const struct rt_host_server *server)
{
    return server && ((server->tcp.watcher.fd >= 0 && server->tcp.authenticated && server->tcp.subscribed) ||
        (server->uart.watcher.fd >= 0 && server->uart.authenticated && server->uart.subscribed));
}

#ifdef RT_HOST_TEST_HOOKS
int rt_host_server_test_emit_uart_prefix(struct rt_host_server *server,
    const uint8_t *prefix, size_t length)
{
    if (!server || server->uart.watcher.fd < 0 || !server->uart.authenticated ||
        !prefix || !length) return -EINVAL;
    size_t used = 0;
    while (used < length) {
        ssize_t count = write(server->uart.watcher.fd, prefix + used, length - used);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return count == 0 ? -EIO : -errno;
        used += (size_t)count;
    }
    return 0;
}
#endif
