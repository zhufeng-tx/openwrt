/* SPDX-License-Identifier: GPL-2.0-only */
#define _GNU_SOURCE
#include "rt_ip_offload.h"
#include "host/rt_host_auth.h"
#include "host/rt_host_framing.h"
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
#include <time.h>
#include <unistd.h>

#define IP_JSON_MAX 8192U
#define IP_INPUT_MAX (IP_JSON_MAX + 4U)
#define IP_OUTPUT_MAX (IP_JSON_MAX * 2U)
#define IP_MAC_BYTES 12U
#ifndef RT_IP_SERVER_IDLE_MS
#define RT_IP_SERVER_IDLE_MS 7000U
#endif

enum ip_state { IP_DISCONNECTED, IP_CONNECTING, IP_AUTH_HELLO, IP_AUTH_PROOF, IP_READY };

struct ip_stream {
    struct uloop_fd watch;
    uint8_t input[IP_INPUT_MAX];
    size_t input_used;
    uint8_t output[IP_OUTPUT_MAX];
    size_t output_used;
};

struct rt_ip_server;
struct server_peer {
    struct ip_stream stream;
    struct rt_ip_server *server;
    enum ip_state state;
    uint8_t eui[RT_IP_EUI_BYTES];
    uint8_t key[RT_IP_KEY_BYTES];
    uint8_t node_id;
    uint8_t client_nonce[RT_HOST_NONCE_BYTES];
    uint8_t server_nonce[RT_HOST_NONCE_BYTES];
    uint32_t last_ping_sequence;
    struct uloop_timeout auth_timeout;
    struct uloop_timeout idle_timeout;
};

struct rt_ip_server {
    struct uloop_fd listener;
    struct server_peer peers[8];
    rt_ip_lookup_cb lookup;
    rt_ip_receive_cb receive;
    void *context;
};

struct rt_ip_client {
    struct ip_stream stream;
    struct uloop_timeout retry_timer;
    struct uloop_timeout heartbeat_timer;
    enum ip_state state;
    struct sockaddr_in address;
    uint8_t eui[RT_IP_EUI_BYTES];
    uint8_t key[RT_IP_KEY_BYTES];
    uint8_t client_nonce[RT_HOST_NONCE_BYTES];
    uint8_t server_nonce[RT_HOST_NONCE_BYTES];
    uint8_t encoded[RT_IP_BLOCK_MAX];
    struct rt_ip_block pending;
    bool has_pending;
    bool has_retired;
    uint32_t retired_stream_id;
    uint16_t retired_block_id;
    uint32_t retired_next_offset;
    uint64_t last_rx_ms;
    uint32_t next_ping_sequence;
    uint32_t last_pong_sequence;
    uint8_t retry_step;
    rt_ip_ack_cb acknowledge;
    rt_ip_state_cb state_cb;
    void *context;
};

static uint64_t monotonic_ms(void)
{
    struct timespec now = {};
    if (clock_gettime(CLOCK_MONOTONIC, &now)) return 0;
    return (uint64_t)now.tv_sec * 1000U + (uint64_t)now.tv_nsec / 1000000U;
}

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

static int hex_digit(unsigned char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

static int hex_decode(const char *text, uint8_t *out, size_t bytes)
{
    if (!text || strlen(text) != bytes * 2) return -EINVAL;
    for (size_t i = 0; i < bytes; i++) {
        int high = hex_digit((unsigned char)text[i * 2]);
        int low = hex_digit((unsigned char)text[i * 2 + 1]);
        if (high < 0 || low < 0) return -EINVAL;
        out[i] = (uint8_t)((high << 4) | low);
    }
    return 0;
}

static void hex_encode(const uint8_t *bytes, size_t length, char *out)
{
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < length; i++) {
        out[i * 2] = digits[bytes[i] >> 4];
        out[i * 2 + 1] = digits[bytes[i] & 15];
    }
    out[length * 2] = '\0';
}

static int base64_decode_exact(const char *text, uint8_t *out, size_t length)
{
    size_t actual = 0;
    if (!text || mbedtls_base64_decode(out, length, &actual,
        (const unsigned char *)text, strlen(text)) || actual != length)
        return -EINVAL;
    return 0;
}

static int base64_encode(const uint8_t *bytes, size_t length,
    char *out, size_t capacity)
{
    size_t actual = 0;
    if (mbedtls_base64_encode((unsigned char *)out, capacity, &actual,
        bytes, length) || actual >= capacity) return -ENOSPC;
    out[actual] = '\0';
    return 0;
}

static int labeled_proof(const uint8_t key[RT_IP_KEY_BYTES], const char *label,
    const uint8_t client_nonce[RT_HOST_NONCE_BYTES],
    const uint8_t server_nonce[RT_HOST_NONCE_BYTES], uint8_t proof[32])
{
    uint8_t message[128];
    size_t label_length = strlen(label) + 1;
    if (label_length + 64 > sizeof(message)) return -EINVAL;
    memcpy(message, label, label_length);
    memcpy(message + label_length, client_nonce, RT_HOST_NONCE_BYTES);
    memcpy(message + label_length + RT_HOST_NONCE_BYTES, server_nonce,
        RT_HOST_NONCE_BYTES);
    return rt_hmac_sha256(key, message, label_length + 64, proof);
}

static void put_u16(uint8_t *out, uint16_t value)
{
    out[0] = (uint8_t)(value >> 8);
    out[1] = (uint8_t)value;
}

static void put_u32(uint8_t *out, uint32_t value)
{
    out[0] = (uint8_t)(value >> 24);
    out[1] = (uint8_t)(value >> 16);
    out[2] = (uint8_t)(value >> 8);
    out[3] = (uint8_t)value;
}

static int block_mac(const uint8_t key[RT_IP_KEY_BYTES],
    const uint8_t client_nonce[RT_HOST_NONCE_BYTES],
    const uint8_t server_nonce[RT_HOST_NONCE_BYTES],
    const struct rt_ip_block *block, uint8_t out[IP_MAC_BYTES])
{
    static const uint8_t label[] = "remoteTester-ip-block-v1";
    uint8_t message[sizeof(label) + 64 + 15 + RT_IP_BLOCK_MAX];
    uint8_t digest[32];
    size_t position = 0;
    if (!block || !block->encoded || block->encoded_length > RT_IP_BLOCK_MAX)
        return -EINVAL;
    memcpy(message + position, label, sizeof(label)); position += sizeof(label);
    memcpy(message + position, client_nonce, 32); position += 32;
    memcpy(message + position, server_nonce, 32); position += 32;
    put_u32(message + position, block->stream_id); position += 4;
    put_u16(message + position, block->block_id); position += 2;
    put_u32(message + position, block->raw_offset); position += 4;
    put_u16(message + position, block->raw_length); position += 2;
    message[position++] = block->codec;
    put_u16(message + position, (uint16_t)block->encoded_length); position += 2;
    memcpy(message + position, block->encoded, block->encoded_length);
    position += block->encoded_length;
    int error = rt_hmac_sha256(key, message, position, digest);
    if (!error) memcpy(out, digest, IP_MAC_BYTES);
    memset(digest, 0, sizeof(digest));
    return error;
}

static int ack_mac(const uint8_t key[RT_IP_KEY_BYTES],
    const uint8_t client_nonce[RT_HOST_NONCE_BYTES],
    const uint8_t server_nonce[RT_HOST_NONCE_BYTES],
    uint32_t stream_id, uint16_t block_id, uint32_t next_offset,
    uint8_t out[IP_MAC_BYTES])
{
    static const uint8_t label[] = "remoteTester-ip-ack-v1";
    uint8_t message[sizeof(label) + 64 + 10], digest[32];
    size_t position = 0;
    memcpy(message + position, label, sizeof(label)); position += sizeof(label);
    memcpy(message + position, client_nonce, 32); position += 32;
    memcpy(message + position, server_nonce, 32); position += 32;
    put_u32(message + position, stream_id); position += 4;
    put_u16(message + position, block_id); position += 2;
    put_u32(message + position, next_offset); position += 4;
    int error = rt_hmac_sha256(key, message, position, digest);
    if (!error) memcpy(out, digest, IP_MAC_BYTES);
    memset(digest, 0, sizeof(digest));
    return error;
}

static int heartbeat_mac(const uint8_t key[RT_IP_KEY_BYTES], bool reply,
    const uint8_t client_nonce[RT_HOST_NONCE_BYTES],
    const uint8_t server_nonce[RT_HOST_NONCE_BYTES], uint32_t sequence,
    uint8_t out[IP_MAC_BYTES])
{
    static const uint8_t ping_label[] = "remoteTester-ip-ping-v1";
    static const uint8_t pong_label[] = "remoteTester-ip-pong-v1";
    const uint8_t *label = reply ? pong_label : ping_label;
    size_t label_length = reply ? sizeof(pong_label) : sizeof(ping_label);
    uint8_t message[sizeof(pong_label) + 64 + 4], digest[32];
    memcpy(message, label, label_length);
    memcpy(message + label_length, client_nonce, 32);
    memcpy(message + label_length + 32, server_nonce, 32);
    put_u32(message + label_length + 64, sequence);
    int error = rt_hmac_sha256(key, message, label_length + 68, digest);
    if (!error) memcpy(out, digest, IP_MAC_BYTES);
    memset(digest, 0, sizeof(digest));
    return error;
}

enum heartbeat_field { HEARTBEAT_SEQUENCE, HEARTBEAT_MAC, __HEARTBEAT_FIELD_MAX };
static const struct blobmsg_policy heartbeat_policy[] = {
    [HEARTBEAT_SEQUENCE] = { .name = "sequence", .type = BLOBMSG_TYPE_INT32 },
    [HEARTBEAT_MAC] = { .name = "mac", .type = BLOBMSG_TYPE_STRING },
};

static int parse_heartbeat(struct blob_buf *message, uint32_t *sequence,
    uint8_t mac[IP_MAC_BYTES])
{
    struct blob_attr *fields[__HEARTBEAT_FIELD_MAX];
    blobmsg_parse(heartbeat_policy, __HEARTBEAT_FIELD_MAX, fields,
        blobmsg_data(message->head), blobmsg_len(message->head));
    if (!fields[HEARTBEAT_SEQUENCE] || !fields[HEARTBEAT_MAC]) return -EINVAL;
    *sequence = blobmsg_get_u32(fields[HEARTBEAT_SEQUENCE]);
    if (!*sequence || hex_decode(blobmsg_get_string(fields[HEARTBEAT_MAC]),
        mac, IP_MAC_BYTES)) return -EINVAL;
    return 0;
}

static int stream_watch(struct ip_stream *stream)
{
    return uloop_fd_add(&stream->watch,
        ULOOP_READ | (stream->output_used ? ULOOP_WRITE : 0));
}

static int stream_queue(struct ip_stream *stream, const char *json)
{
    uint8_t header[4];
    size_t length = strlen(json);
    if (length == 0 || length > IP_JSON_MAX ||
        length + 4 > sizeof(stream->output) - stream->output_used)
        return -ENOSPC;
    if (rt_host_tcp_header(length, header)) return -EINVAL;
    memcpy(stream->output + stream->output_used, header, 4);
    memcpy(stream->output + stream->output_used + 4, json, length);
    stream->output_used += length + 4;
    return stream_watch(stream);
}

static int stream_send_blob(struct ip_stream *stream, struct blob_buf *buffer)
{
    char *json = blobmsg_format_json(buffer->head, true);
    int result;
    if (!json) return -ENOMEM;
    result = stream_queue(stream, json);
    free(json);
    return result;
}

static int stream_flush(struct ip_stream *stream)
{
    while (stream->output_used) {
        ssize_t count = write(stream->watch.fd, stream->output, stream->output_used);
        if (count < 0 && errno == EINTR) continue;
        if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) break;
        if (count <= 0) return count == 0 ? -EPIPE : -errno;
        stream->output_used -= (size_t)count;
        memmove(stream->output, stream->output + count, stream->output_used);
    }
    return stream_watch(stream);
}

static void stream_close(struct ip_stream *stream)
{
    if (stream->watch.fd >= 0) {
        uloop_fd_delete(&stream->watch);
        close(stream->watch.fd);
    }
    stream->watch.fd = -1;
    stream->input_used = stream->output_used = 0;
}

static int stream_next_json(struct ip_stream *stream, char json[IP_JSON_MAX + 1])
{
    uint32_t length;
    if (stream->input_used < 4) return 0;
    length = rt_host_tcp_length(stream->input);
    if (length == 0 || length > IP_JSON_MAX) return -EMSGSIZE;
    if (stream->input_used < length + 4) return 0;
    memcpy(json, stream->input + 4, length);
    json[length] = '\0';
    stream->input_used -= length + 4;
    memmove(stream->input, stream->input + length + 4, stream->input_used);
    return 1;
}

static const struct blobmsg_policy type_policy[] = {
    { .name = "type", .type = BLOBMSG_TYPE_STRING },
};

static int parse_json(const char *json, struct blob_buf *buffer,
    const char **type)
{
    struct blob_attr *fields[1];
    blob_buf_init(buffer, 0);
    if (!blobmsg_add_json_from_string(buffer, json)) return -EBADMSG;
    blobmsg_parse(type_policy, 1, fields,
        blobmsg_data(buffer->head), blobmsg_len(buffer->head));
    if (!fields[0]) return -EBADMSG;
    *type = blobmsg_get_string(fields[0]);
    return 0;
}

enum hello_field { HELLO_EUI, HELLO_NONCE, __HELLO_FIELD_MAX };
static const struct blobmsg_policy hello_policy[] = {
    [HELLO_EUI] = { .name = "eui", .type = BLOBMSG_TYPE_STRING },
    [HELLO_NONCE] = { .name = "clientNonce", .type = BLOBMSG_TYPE_STRING },
};
static const struct blobmsg_policy proof_policy[] = {
    { .name = "proof", .type = BLOBMSG_TYPE_STRING },
};
enum block_field {
    BLOCK_STREAM, BLOCK_ID, BLOCK_OFFSET, BLOCK_RAW_LENGTH, BLOCK_CODEC,
    BLOCK_DATA, BLOCK_MAC, __BLOCK_FIELD_MAX
};
static const struct blobmsg_policy block_policy[] = {
    [BLOCK_STREAM] = { .name = "streamEpoch", .type = BLOBMSG_TYPE_INT32 },
    [BLOCK_ID] = { .name = "blockId", .type = BLOBMSG_TYPE_INT32 },
    [BLOCK_OFFSET] = { .name = "offset", .type = BLOBMSG_TYPE_INT32 },
    [BLOCK_RAW_LENGTH] = { .name = "rawLength", .type = BLOBMSG_TYPE_INT32 },
    [BLOCK_CODEC] = { .name = "codec", .type = BLOBMSG_TYPE_STRING },
    [BLOCK_DATA] = { .name = "data", .type = BLOBMSG_TYPE_STRING },
    [BLOCK_MAC] = { .name = "mac", .type = BLOBMSG_TYPE_STRING },
};

static void server_peer_close(struct server_peer *peer)
{
    uloop_timeout_cancel(&peer->auth_timeout);
    uloop_timeout_cancel(&peer->idle_timeout);
    stream_close(&peer->stream);
    peer->state = IP_DISCONNECTED;
    peer->node_id = 0;
    peer->last_ping_sequence = 0;
    memset(peer->key, 0, sizeof(peer->key));
    memset(peer->client_nonce, 0, sizeof(peer->client_nonce));
    memset(peer->server_nonce, 0, sizeof(peer->server_nonce));
}

static int server_challenge(struct server_peer *peer, struct blob_buf *request)
{
    struct blob_attr *fields[__HELLO_FIELD_MAX];
    struct blob_buf reply = {};
    uint8_t proof[32];
    char encoded_nonce[64], encoded_proof[65];
    int error;
    blobmsg_parse(hello_policy, __HELLO_FIELD_MAX, fields,
        blobmsg_data(request->head), blobmsg_len(request->head));
    if (!fields[HELLO_EUI] || !fields[HELLO_NONCE] ||
        hex_decode(blobmsg_get_string(fields[HELLO_EUI]), peer->eui, 8) ||
        base64_decode_exact(blobmsg_get_string(fields[HELLO_NONCE]),
            peer->client_nonce, 32)) return -EINVAL;
    error = peer->server->lookup(peer->server->context, peer->eui,
        peer->key, &peer->node_id);
    if (error || peer->node_id == 0 || peer->node_id > 8) return -EACCES;
    error = rt_host_random_nonce(peer->server_nonce);
    if (error) return error;
    error = labeled_proof(peer->key, "remoteTester-node-server-v1",
        peer->client_nonce, peer->server_nonce, proof);
    if (error) return error;
    hex_encode(proof, 32, encoded_proof);
    memset(proof, 0, sizeof(proof));
    error = base64_encode(peer->server_nonce, 32, encoded_nonce,
        sizeof(encoded_nonce));
    if (error) return error;
    blob_buf_init(&reply, 0);
    blobmsg_add_string(&reply, "type", "node.auth.challenge");
    blobmsg_add_string(&reply, "serverNonce", encoded_nonce);
    blobmsg_add_string(&reply, "serverProof", encoded_proof);
    error = stream_send_blob(&peer->stream, &reply);
    blob_buf_free(&reply);
    if (!error) peer->state = IP_AUTH_PROOF;
    return error;
}

static int server_check_proof(struct server_peer *peer, struct blob_buf *request)
{
    struct blob_attr *fields[1];
    struct blob_buf reply = {};
    uint8_t actual[32], expected[32];
    int error;
    blobmsg_parse(proof_policy, 1, fields,
        blobmsg_data(request->head), blobmsg_len(request->head));
    if (!fields[0] || hex_decode(blobmsg_get_string(fields[0]), actual, 32))
        return -EINVAL;
    error = labeled_proof(peer->key, "remoteTester-node-v1",
        peer->client_nonce, peer->server_nonce, expected);
    if (!error) error = rt_host_proof_verify(expected, actual);
    memset(expected, 0, sizeof(expected));
    memset(actual, 0, sizeof(actual));
    if (error) return error;
    blob_buf_init(&reply, 0);
    blobmsg_add_string(&reply, "type", "node.auth.ok");
    error = stream_send_blob(&peer->stream, &reply);
    blob_buf_free(&reply);
    if (!error) {
        peer->state = IP_READY;
        uloop_timeout_cancel(&peer->auth_timeout);
        uloop_timeout_set(&peer->idle_timeout, RT_IP_SERVER_IDLE_MS);
    }
    return error;
}

static int server_accept_block(struct server_peer *peer, struct blob_buf *request)
{
    struct blob_attr *fields[__BLOCK_FIELD_MAX];
    struct rt_ip_block block = {};
    struct blob_buf reply = {};
    uint8_t encoded[RT_IP_BLOCK_MAX], actual[IP_MAC_BYTES], expected[IP_MAC_BYTES];
    uint8_t ack[IP_MAC_BYTES];
    size_t encoded_length = 0;
    char ack_hex[IP_MAC_BYTES * 2 + 1];
    uint32_t next_offset;
    const char *codec, *data;
    int error;
    blobmsg_parse(block_policy, __BLOCK_FIELD_MAX, fields,
        blobmsg_data(request->head), blobmsg_len(request->head));
    for (size_t i = 0; i < __BLOCK_FIELD_MAX; i++) if (!fields[i]) return -EINVAL;
    block.stream_id = blobmsg_get_u32(fields[BLOCK_STREAM]);
    if (blobmsg_get_u32(fields[BLOCK_ID]) > UINT16_MAX ||
        blobmsg_get_u32(fields[BLOCK_RAW_LENGTH]) > RT_IP_BLOCK_MAX) return -EINVAL;
    block.block_id = (uint16_t)blobmsg_get_u32(fields[BLOCK_ID]);
    block.raw_offset = blobmsg_get_u32(fields[BLOCK_OFFSET]);
    block.raw_length = (uint16_t)blobmsg_get_u32(fields[BLOCK_RAW_LENGTH]);
    if (block.raw_offset > UINT32_MAX - block.raw_length) return -EINVAL;
    codec = blobmsg_get_string(fields[BLOCK_CODEC]);
    block.codec = !strcmp(codec, "raw") ? 0 : !strcmp(codec, "deflate") ? 1 : 255;
    if (block.codec > 1 || block.raw_length == 0) return -EINVAL;
    data = blobmsg_get_string(fields[BLOCK_DATA]);
    error = mbedtls_base64_decode(encoded, sizeof(encoded), &encoded_length,
        (const unsigned char *)data, strlen(data));
    if (error || encoded_length == 0) return -EINVAL;
    block.encoded = encoded;
    block.encoded_length = encoded_length;
    if (hex_decode(blobmsg_get_string(fields[BLOCK_MAC]), actual, sizeof(actual)))
        return -EINVAL;
    error = block_mac(peer->key, peer->client_nonce, peer->server_nonce,
        &block, expected);
    if (error) return error;
    uint8_t difference = 0;
    for (size_t i = 0; i < sizeof(actual); i++) difference |= actual[i] ^ expected[i];
    if (difference) return -EACCES;
    error = peer->server->receive(peer->server->context, peer->node_id,
        &block, &next_offset);
    if (error) return error;
    error = ack_mac(peer->key, peer->client_nonce, peer->server_nonce,
        block.stream_id, block.block_id, next_offset, ack);
    if (error) return error;
    hex_encode(ack, sizeof(ack), ack_hex);
    blob_buf_init(&reply, 0);
    blobmsg_add_string(&reply, "type", "serial.ack");
    blobmsg_add_u32(&reply, "streamEpoch", block.stream_id);
    blobmsg_add_u32(&reply, "blockId", block.block_id);
    blobmsg_add_u32(&reply, "nextOffset", next_offset);
    blobmsg_add_string(&reply, "mac", ack_hex);
    error = stream_send_blob(&peer->stream, &reply);
    blob_buf_free(&reply);
    return error;
}

static int server_accept_ping(struct server_peer *peer, struct blob_buf *request)
{
    struct blob_buf reply = {};
    uint8_t actual[IP_MAC_BYTES], expected[IP_MAC_BYTES], answer[IP_MAC_BYTES];
    char answer_hex[IP_MAC_BYTES * 2 + 1];
    uint8_t difference = 0;
    uint32_t sequence;
    int error = parse_heartbeat(request, &sequence, actual);
    if (error || sequence <= peer->last_ping_sequence) return -EACCES;
    error = heartbeat_mac(peer->key, false, peer->client_nonce,
        peer->server_nonce, sequence, expected);
    if (error) return error;
    for (size_t i = 0; i < IP_MAC_BYTES; i++) difference |= actual[i] ^ expected[i];
    if (difference) return -EACCES;
    peer->last_ping_sequence = sequence;
    error = heartbeat_mac(peer->key, true, peer->client_nonce,
        peer->server_nonce, sequence, answer);
    if (error) return error;
    hex_encode(answer, IP_MAC_BYTES, answer_hex);
    blob_buf_init(&reply, 0);
    blobmsg_add_string(&reply, "type", "node.pong");
    blobmsg_add_u32(&reply, "sequence", sequence);
    blobmsg_add_string(&reply, "mac", answer_hex);
    error = stream_send_blob(&peer->stream, &reply);
    blob_buf_free(&reply);
    return error;
}

static int server_handle_json(struct server_peer *peer, const char *json)
{
    struct blob_buf request = {};
    const char *type = NULL;
    int error = parse_json(json, &request, &type);
    if (error) goto out;
    if (peer->state == IP_AUTH_HELLO && !strcmp(type, "node.auth.hello"))
        error = server_challenge(peer, &request);
    else if (peer->state == IP_AUTH_PROOF && !strcmp(type, "node.auth.proof"))
        error = server_check_proof(peer, &request);
    else if (peer->state == IP_READY && !strcmp(type, "serial.block"))
        error = server_accept_block(peer, &request);
    else if (peer->state == IP_READY && !strcmp(type, "node.ping"))
        error = server_accept_ping(peer, &request);
    else error = -EPROTO;
out:
    blob_buf_free(&request);
    return error;
}

static void server_auth_timeout(struct uloop_timeout *timer)
{
    struct server_peer *peer = container_of(timer, struct server_peer, auth_timeout);
    if (peer->state != IP_READY) server_peer_close(peer);
}

static void server_idle_timeout(struct uloop_timeout *timer)
{
    struct server_peer *peer = container_of(timer, struct server_peer, idle_timeout);
    server_peer_close(peer);
}

static void server_peer_cb(struct uloop_fd *watch, unsigned int events)
{
    struct server_peer *peer = container_of(watch, struct server_peer, stream.watch);
    if (events & ULOOP_READ) {
        for (;;) {
            char json[IP_JSON_MAX + 1];
            ssize_t count = read(watch->fd, peer->stream.input + peer->stream.input_used,
                sizeof(peer->stream.input) - peer->stream.input_used);
            if (count < 0 && errno == EINTR) continue;
            if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) break;
            if (count <= 0) { server_peer_close(peer); return; }
            peer->stream.input_used += (size_t)count;
            for (;;) {
                int next = stream_next_json(&peer->stream, json);
                if (next < 0) {
                    server_peer_close(peer); return;
                }
                if (next == 0) break;
                if (server_handle_json(peer, json)) { server_peer_close(peer); return; }
                if (peer->state == IP_READY)
                    uloop_timeout_set(&peer->idle_timeout, RT_IP_SERVER_IDLE_MS);
            }
            if (peer->stream.input_used == sizeof(peer->stream.input)) {
                server_peer_close(peer); return;
            }
        }
    }
    if ((events & ULOOP_WRITE) && stream_flush(&peer->stream)) server_peer_close(peer);
}

static void server_listener_cb(struct uloop_fd *watch, unsigned int events)
{
    struct rt_ip_server *server = container_of(watch, struct rt_ip_server, listener);
    (void)events;
    for (;;) {
        int fd = accept(watch->fd, NULL, NULL);
        if (fd < 0 && errno == EINTR) continue;
        if (fd < 0) return;
        struct server_peer *peer = NULL;
        for (size_t i = 0; i < 8; i++)
            if (server->peers[i].stream.watch.fd < 0) { peer = &server->peers[i]; break; }
        if (!peer) { close(fd); continue; }
        int flags = fcntl(fd, F_GETFL);
        if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK)) { close(fd); continue; }
        peer->stream.watch.fd = fd;
        peer->state = IP_AUTH_HELLO;
        if (stream_watch(&peer->stream)) { server_peer_close(peer); continue; }
        uloop_timeout_set(&peer->auth_timeout, 5000);
    }
}

struct rt_ip_server *rt_ip_server_start(uint16_t port,
    rt_ip_lookup_cb lookup, rt_ip_receive_cb receive, void *context)
{
    struct rt_ip_server *server;
    struct sockaddr_in address = { .sin_family = AF_INET, .sin_addr.s_addr = INADDR_ANY };
    int fd, enabled = 1;
    if (!port || !lookup || !receive) { errno = EINVAL; return NULL; }
    server = calloc(1, sizeof(*server));
    if (!server) return NULL;
    server->listener.fd = -1;
    server->listener.cb = server_listener_cb;
    server->lookup = lookup;
    server->receive = receive;
    server->context = context;
    for (size_t i = 0; i < 8; i++) {
        server->peers[i].stream.watch.fd = -1;
        server->peers[i].stream.watch.cb = server_peer_cb;
        server->peers[i].server = server;
        server->peers[i].auth_timeout.cb = server_auth_timeout;
        server->peers[i].idle_timeout.cb = server_idle_timeout;
    }
    fd = open_tcp_socket();
    if (fd < 0) goto fail;
    (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof(enabled));
    address.sin_port = htons(port);
    if (bind(fd, (struct sockaddr *)&address, sizeof(address)) || listen(fd, 8)) {
        int saved = errno;
        close(fd);
        errno = saved;
        goto fail;
    }
    server->listener.fd = fd;
    if (uloop_fd_add(&server->listener, ULOOP_READ)) goto fail;
    return server;
fail: {
    int saved = errno;
    rt_ip_server_stop(server);
    errno = saved;
    return NULL;
}
}

void rt_ip_server_stop(struct rt_ip_server *server)
{
    if (!server) return;
    for (size_t i = 0; i < 8; i++) server_peer_close(&server->peers[i]);
    if (server->listener.fd >= 0) {
        uloop_fd_delete(&server->listener);
        close(server->listener.fd);
    }
    free(server);
}

static void client_retry_cb(struct uloop_timeout *timer);
static void client_heartbeat_cb(struct uloop_timeout *timer);

static void client_disconnect(struct rt_ip_client *client, bool retry)
{
    bool was_ready = client->state == IP_READY;
    stream_close(&client->stream);
    client->state = IP_DISCONNECTED;
    client->has_retired = false;
    client->next_ping_sequence = client->last_pong_sequence = 0;
    uloop_timeout_cancel(&client->heartbeat_timer);
    memset(client->client_nonce, 0, sizeof(client->client_nonce));
    memset(client->server_nonce, 0, sizeof(client->server_nonce));
    if (was_ready && client->state_cb) client->state_cb(client->context, false);
    if (retry) {
        static const int delays[] = {250, 500, 1000, 2000};
        unsigned step = client->retry_step < 3 ? client->retry_step++ : 3;
        uloop_timeout_set(&client->retry_timer, delays[step]);
    }
}

static int client_send_hello(struct rt_ip_client *client)
{
    struct blob_buf request = {};
    char eui[17], nonce[64];
    int error = rt_host_random_nonce(client->client_nonce);
    if (error) return error;
    error = base64_encode(client->client_nonce, 32, nonce, sizeof(nonce));
    if (error) return error;
    hex_encode(client->eui, 8, eui);
    blob_buf_init(&request, 0);
    blobmsg_add_string(&request, "type", "node.auth.hello");
    blobmsg_add_string(&request, "eui", eui);
    blobmsg_add_string(&request, "clientNonce", nonce);
    error = stream_send_blob(&client->stream, &request);
    blob_buf_free(&request);
    if (!error) {
        client->state = IP_AUTH_HELLO;
        client->last_rx_ms = monotonic_ms();
        uloop_timeout_set(&client->heartbeat_timer, 2000);
    }
    return error;
}

static int client_send_pending(struct rt_ip_client *client)
{
    struct blob_buf request = {};
    uint8_t mac[IP_MAC_BYTES];
    char mac_hex[IP_MAC_BYTES * 2 + 1];
    char data[RT_IP_BLOCK_MAX * 4 / 3 + 8];
    int error;
    if (!client->has_pending || client->state != IP_READY) return -ENOTCONN;
    error = block_mac(client->key, client->client_nonce, client->server_nonce,
        &client->pending, mac);
    if (error) return error;
    hex_encode(mac, sizeof(mac), mac_hex);
    error = base64_encode(client->pending.encoded,
        client->pending.encoded_length, data, sizeof(data));
    if (error) return error;
    blob_buf_init(&request, 0);
    blobmsg_add_string(&request, "type", "serial.block");
    blobmsg_add_u32(&request, "streamEpoch", client->pending.stream_id);
    blobmsg_add_u32(&request, "blockId", client->pending.block_id);
    blobmsg_add_u32(&request, "offset", client->pending.raw_offset);
    blobmsg_add_u32(&request, "rawLength", client->pending.raw_length);
    blobmsg_add_string(&request, "codec", client->pending.codec ? "deflate" : "raw");
    blobmsg_add_string(&request, "data", data);
    blobmsg_add_string(&request, "mac", mac_hex);
    error = stream_send_blob(&client->stream, &request);
    blob_buf_free(&request);
    return error;
}

enum challenge_field { CHALLENGE_NONCE, CHALLENGE_PROOF, __CHALLENGE_FIELD_MAX };
static const struct blobmsg_policy challenge_policy[] = {
    [CHALLENGE_NONCE] = { .name = "serverNonce", .type = BLOBMSG_TYPE_STRING },
    [CHALLENGE_PROOF] = { .name = "serverProof", .type = BLOBMSG_TYPE_STRING },
};
enum ack_field { ACK_STREAM, ACK_BLOCK, ACK_NEXT, ACK_MAC, __ACK_FIELD_MAX };
static const struct blobmsg_policy ack_policy[] = {
    [ACK_STREAM] = { .name = "streamEpoch", .type = BLOBMSG_TYPE_INT32 },
    [ACK_BLOCK] = { .name = "blockId", .type = BLOBMSG_TYPE_INT32 },
    [ACK_NEXT] = { .name = "nextOffset", .type = BLOBMSG_TYPE_INT32 },
    [ACK_MAC] = { .name = "mac", .type = BLOBMSG_TYPE_STRING },
};

static int client_challenge(struct rt_ip_client *client, struct blob_buf *response)
{
    struct blob_attr *fields[__CHALLENGE_FIELD_MAX];
    struct blob_buf request = {};
    uint8_t expected[32], actual[32], proof[32];
    char encoded_proof[65];
    int error;
    blobmsg_parse(challenge_policy, __CHALLENGE_FIELD_MAX, fields,
        blobmsg_data(response->head), blobmsg_len(response->head));
    if (!fields[CHALLENGE_NONCE] || !fields[CHALLENGE_PROOF] ||
        base64_decode_exact(blobmsg_get_string(fields[CHALLENGE_NONCE]),
            client->server_nonce, 32) ||
        hex_decode(blobmsg_get_string(fields[CHALLENGE_PROOF]), actual, 32))
        return -EINVAL;
    error = labeled_proof(client->key, "remoteTester-node-server-v1",
        client->client_nonce, client->server_nonce, expected);
    if (!error) error = rt_host_proof_verify(expected, actual);
    memset(expected, 0, sizeof(expected));
    memset(actual, 0, sizeof(actual));
    if (error) return error;
    error = labeled_proof(client->key, "remoteTester-node-v1",
        client->client_nonce, client->server_nonce, proof);
    if (error) return error;
    hex_encode(proof, 32, encoded_proof);
    memset(proof, 0, sizeof(proof));
    blob_buf_init(&request, 0);
    blobmsg_add_string(&request, "type", "node.auth.proof");
    blobmsg_add_string(&request, "proof", encoded_proof);
    error = stream_send_blob(&client->stream, &request);
    blob_buf_free(&request);
    if (!error) client->state = IP_AUTH_PROOF;
    return error;
}

static int client_accept_ack(struct rt_ip_client *client, struct blob_buf *response)
{
    struct blob_attr *fields[__ACK_FIELD_MAX];
    uint8_t actual[IP_MAC_BYTES], expected[IP_MAC_BYTES], difference = 0;
    uint32_t stream_id, next_offset;
    uint16_t block_id;
    int error;
    blobmsg_parse(ack_policy, __ACK_FIELD_MAX, fields,
        blobmsg_data(response->head), blobmsg_len(response->head));
    for (size_t i = 0; i < __ACK_FIELD_MAX; i++) if (!fields[i]) return -EINVAL;
    if (blobmsg_get_u32(fields[ACK_BLOCK]) > UINT16_MAX) return -EINVAL;
    stream_id = blobmsg_get_u32(fields[ACK_STREAM]);
    block_id = (uint16_t)blobmsg_get_u32(fields[ACK_BLOCK]);
    next_offset = blobmsg_get_u32(fields[ACK_NEXT]);
    bool pending_match = client->has_pending && stream_id == client->pending.stream_id &&
        block_id == client->pending.block_id &&
        next_offset == client->pending.raw_offset + client->pending.raw_length;
    bool retired_match = client->has_retired && stream_id == client->retired_stream_id &&
        block_id == client->retired_block_id && next_offset == client->retired_next_offset;
    if (!pending_match && !retired_match)
        return -EBADMSG;
    if (hex_decode(blobmsg_get_string(fields[ACK_MAC]), actual, sizeof(actual)))
        return -EINVAL;
    error = ack_mac(client->key, client->client_nonce, client->server_nonce,
        stream_id, block_id, next_offset, expected);
    if (error) return error;
    for (size_t i = 0; i < sizeof(actual); i++) difference |= actual[i] ^ expected[i];
    if (difference) return -EACCES;
    if (retired_match && !pending_match) return 0;
    client->has_pending = false;
    client->has_retired = true;
    client->retired_stream_id = stream_id;
    client->retired_block_id = block_id;
    client->retired_next_offset = next_offset;
    if (client->acknowledge)
        client->acknowledge(client->context, stream_id, block_id, next_offset);
    return 0;
}

static int client_accept_pong(struct rt_ip_client *client, struct blob_buf *response)
{
    uint8_t actual[IP_MAC_BYTES], expected[IP_MAC_BYTES], difference = 0;
    uint32_t sequence;
    int error = parse_heartbeat(response, &sequence, actual);
    if (error || sequence <= client->last_pong_sequence ||
        sequence > client->next_ping_sequence) return -EACCES;
    error = heartbeat_mac(client->key, true, client->client_nonce,
        client->server_nonce, sequence, expected);
    if (error) return error;
    for (size_t i = 0; i < IP_MAC_BYTES; i++) difference |= actual[i] ^ expected[i];
    if (difference) return -EACCES;
    client->last_pong_sequence = sequence;
    return 0;
}

static int client_handle_json(struct rt_ip_client *client, const char *json)
{
    struct blob_buf response = {};
    const char *type = NULL;
    int error = parse_json(json, &response, &type);
    if (error) goto out;
    if (client->state == IP_AUTH_HELLO && !strcmp(type, "node.auth.challenge"))
        error = client_challenge(client, &response);
    else if (client->state == IP_AUTH_PROOF && !strcmp(type, "node.auth.ok")) {
        client->state = IP_READY;
        client->retry_step = 0;
        if (client->has_pending) error = client_send_pending(client);
        if (!error && client->state_cb) client->state_cb(client->context, true);
    } else if (client->state == IP_READY && !strcmp(type, "serial.ack"))
        error = client_accept_ack(client, &response);
    else if (client->state == IP_READY && !strcmp(type, "node.pong"))
        error = client_accept_pong(client, &response);
    else error = -EPROTO;
    if (!error) client->last_rx_ms = monotonic_ms();
out:
    blob_buf_free(&response);
    return error;
}

static void client_cb(struct uloop_fd *watch, unsigned int events)
{
    struct rt_ip_client *client = container_of(watch, struct rt_ip_client, stream.watch);
    if (client->state == IP_CONNECTING && (events & ULOOP_WRITE)) {
        int error = 0;
        socklen_t length = sizeof(error);
        if (getsockopt(watch->fd, SOL_SOCKET, SO_ERROR, &error, &length) || error ||
            client_send_hello(client)) {
            client_disconnect(client, true);
            return;
        }
    }
    if (events & ULOOP_READ) {
        for (;;) {
            char json[IP_JSON_MAX + 1];
            ssize_t count = read(watch->fd,
                client->stream.input + client->stream.input_used,
                sizeof(client->stream.input) - client->stream.input_used);
            if (count < 0 && errno == EINTR) continue;
            if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) break;
            if (count <= 0) { client_disconnect(client, true); return; }
            client->stream.input_used += (size_t)count;
            for (;;) {
                int next = stream_next_json(&client->stream, json);
                if (next < 0 || (next > 0 && client_handle_json(client, json))) {
                    client_disconnect(client, true); return;
                }
                if (next == 0) break;
            }
            if (client->stream.input_used == sizeof(client->stream.input)) {
                client_disconnect(client, true); return;
            }
        }
    }
    if ((events & ULOOP_WRITE) && stream_flush(&client->stream))
        client_disconnect(client, true);
}

static void client_retry_cb(struct uloop_timeout *timer)
{
    struct rt_ip_client *client = container_of(timer, struct rt_ip_client, retry_timer);
    int fd, error;
    fd = open_tcp_socket();
    if (fd < 0) { client_disconnect(client, true); return; }
    client->stream.watch.fd = fd;
    client->state = IP_CONNECTING;
    error = connect(fd, (struct sockaddr *)&client->address, sizeof(client->address));
    if (error && errno != EINPROGRESS) { client_disconnect(client, true); return; }
    if (!error) {
        if (client_send_hello(client)) { client_disconnect(client, true); return; }
    }
    if (uloop_fd_add(&client->stream.watch, ULOOP_READ | ULOOP_WRITE))
        client_disconnect(client, true);
}

static void client_heartbeat_cb(struct uloop_timeout *timer)
{
    struct rt_ip_client *client = container_of(timer, struct rt_ip_client, heartbeat_timer);
    uint64_t now = monotonic_ms();
    if (!now || now - client->last_rx_ms > 5000) {
        client_disconnect(client, true);
        return;
    }
    if (client->state == IP_READY) {
        struct blob_buf request = {};
        uint8_t tag[IP_MAC_BYTES];
        char tag_hex[IP_MAC_BYTES * 2 + 1];
        if (client->next_ping_sequence == UINT32_MAX ||
            heartbeat_mac(client->key, false, client->client_nonce,
                client->server_nonce, client->next_ping_sequence + 1, tag)) {
            client_disconnect(client, true);
            return;
        }
        client->next_ping_sequence++;
        hex_encode(tag, IP_MAC_BYTES, tag_hex);
        blob_buf_init(&request, 0);
        blobmsg_add_string(&request, "type", "node.ping");
        blobmsg_add_u32(&request, "sequence", client->next_ping_sequence);
        blobmsg_add_string(&request, "mac", tag_hex);
        if (stream_send_blob(&client->stream, &request)) {
            blob_buf_free(&request);
            client_disconnect(client, true);
            return;
        }
        blob_buf_free(&request);
    }
    uloop_timeout_set(&client->heartbeat_timer, 2000);
}

struct rt_ip_client *rt_ip_client_start(const char *controller_ipv4, uint16_t port,
    const uint8_t eui[RT_IP_EUI_BYTES], const uint8_t key[RT_IP_KEY_BYTES],
    rt_ip_ack_cb acknowledge, rt_ip_state_cb state, void *context)
{
    struct rt_ip_client *client;
    if (!controller_ipv4 || !port || !eui || !key) { errno = EINVAL; return NULL; }
    client = calloc(1, sizeof(*client));
    if (!client) return NULL;
    client->stream.watch.fd = -1;
    client->stream.watch.cb = client_cb;
    client->retry_timer.cb = client_retry_cb;
    client->heartbeat_timer.cb = client_heartbeat_cb;
    client->address.sin_family = AF_INET;
    client->address.sin_port = htons(port);
    if (inet_pton(AF_INET, controller_ipv4, &client->address.sin_addr) != 1) {
        free(client);
        errno = EINVAL;
        return NULL;
    }
    memcpy(client->eui, eui, RT_IP_EUI_BYTES);
    memcpy(client->key, key, RT_IP_KEY_BYTES);
    client->acknowledge = acknowledge;
    client->state_cb = state;
    client->context = context;
    if (uloop_timeout_set(&client->retry_timer, 0)) {
        free(client);
        errno = EIO;
        return NULL;
    }
    /* Notify the owner that an IP route is not healthy before the first
     * connection attempt; retained blocks must be eligible for RF fallback. */
    if (client->state_cb) client->state_cb(client->context, false);
    return client;
}

void rt_ip_client_stop(struct rt_ip_client *client)
{
    if (!client) return;
    uloop_timeout_cancel(&client->retry_timer);
    uloop_timeout_cancel(&client->heartbeat_timer);
    client_disconnect(client, false);
    memset(client->key, 0, sizeof(client->key));
    free(client);
}

int rt_ip_client_send(struct rt_ip_client *client, const struct rt_ip_block *block)
{
    if (!client || !block || !block->encoded || !block->encoded_length ||
        block->encoded_length > RT_IP_BLOCK_MAX || !block->raw_length ||
        block->raw_length > RT_IP_BLOCK_MAX || block->codec > 1 ||
        block->raw_offset > UINT32_MAX - block->raw_length)
        return -EINVAL;
    if (client->state != IP_READY) return -ENOTCONN;
    if (client->has_pending) return -EBUSY;
    memcpy(client->encoded, block->encoded, block->encoded_length);
    client->pending = *block;
    client->pending.encoded = client->encoded;
    client->has_pending = true;
    int error = client_send_pending(client);
    if (error) client->has_pending = false;
    return error;
}

void rt_ip_client_cancel_pending(struct rt_ip_client *client, uint32_t stream_id,
    uint16_t block_id)
{
    if (client && client->has_pending && client->pending.stream_id == stream_id &&
        client->pending.block_id == block_id) {
        client->has_retired = true;
        client->retired_stream_id = stream_id;
        client->retired_block_id = block_id;
        client->retired_next_offset = client->pending.raw_offset + client->pending.raw_length;
        client->has_pending = false;
    }
}

bool rt_ip_client_healthy(const struct rt_ip_client *client)
{
    uint64_t now = monotonic_ms();
    return client && client->state == IP_READY && now &&
        now - client->last_rx_ms <= 5000;
}
