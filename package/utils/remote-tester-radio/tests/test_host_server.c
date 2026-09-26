/* SPDX-License-Identifier: GPL-2.0-only */
#include "../src/host/rt_host_auth.h"
#include "../src/host/rt_host_framing.h"
#include "../src/host/rt_host_server.h"
#include "../src/host/rt_host_secure.h"
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <json-c/json.h>
#include <libubox/blobmsg.h>
#include <libubox/uloop.h>
#include <libubox/utils.h>
#include <netinet/in.h>
#include <openssl/evp.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>

static int request_cb(void *context, const char *type, const char *request_id,
    uint8_t node_id, struct blob_attr *payload, struct blob_buf *result)
{
    (void)context; (void)request_id; (void)node_id; (void)payload;
    if (strcmp(type, "node.discover")) return -EINVAL;
    void *nodes = blobmsg_open_array(result, "nodes");
    void *node = blobmsg_open_table(result, NULL);
    blobmsg_add_u32(result, "nodeId", 1);
    blobmsg_add_string(result, "mac", "0011223344556677");
    blobmsg_close_table(result, node);
    blobmsg_close_array(result, nodes);
    return 0;
}

static void read_exact(int fd, uint8_t *bytes, size_t length)
{
    while (length) {
        ssize_t count = read(fd, bytes, length);
        assert(count > 0);
        bytes += count;
        length -= (size_t)count;
    }
}

static void write_exact(int fd, const uint8_t *bytes, size_t length)
{
    while (length) {
        ssize_t count = write(fd, bytes, length);
        assert(count > 0);
        bytes += count;
        length -= (size_t)count;
    }
}

static bool secure_active;
static uint8_t session_key[32];
static uint64_t outgoing_sequence, incoming_sequence;

static void send_json(int fd, const char *json)
{
    uint8_t header[4];
    uint8_t secured[8192 + RT_HOST_SECURE_TRAILER_BYTES];
    size_t length = strlen(json);
    const uint8_t *body = (const uint8_t *)json;
    if (secure_active) {
        assert(rt_host_secure_wrap(session_key, false, ++outgoing_sequence,
            body, length, secured, sizeof(secured), &length) == 0);
        body = secured;
    }
    assert(rt_host_tcp_header(length, header) == 0);
    write_exact(fd, header, 4);
    write_exact(fd, body, length);
}

static struct json_object *receive_json(int fd)
{
    uint8_t header[4];
    read_exact(fd, header, 4);
    uint32_t length = rt_host_tcp_length(header);
    assert(length > 0 && length < 8192 + RT_HOST_SECURE_TRAILER_BYTES);
    char *json = malloc(length + 1);
    assert(json);
    read_exact(fd, (uint8_t *)json, length);
    if (secure_active) {
        uint8_t plain[8192];
        size_t plain_length;
        assert(rt_host_secure_unwrap(session_key, true, ++incoming_sequence,
            (const uint8_t *)json, length, plain, sizeof(plain), &plain_length) == 0);
        memcpy(json, plain, plain_length);
        length = (uint32_t)plain_length;
    }
    json[length] = '\0';
    struct json_object *object = json_tokener_parse(json);
    free(json);
    assert(object);
    return object;
}

static const char *member_string(struct json_object *object, const char *name)
{
    struct json_object *field;
    assert(json_object_object_get_ex(object, name, &field));
    return json_object_get_string(field);
}

static void proof_hex(const uint8_t proof[32], char out[65])
{
    for (size_t i = 0; i < 32; i++) snprintf(out + i * 2, 3, "%02x", proof[i]);
}

static int client_flow(uint16_t port)
{
    static const char request_id[] = "123e4567-e89b-42d3-a456-426614174000";
    struct sockaddr_in address = { .sin_family = AF_INET, .sin_port = htons(port) };
    uint8_t key[32], client_nonce[32], server_nonce[32], decoded_nonce[64], proof[32];
    char encoded_nonce[64], text[512], hex[65];
    struct timeval timeout = { .tv_sec = 2 };
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    assert(fd >= 0);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    assert(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0);
    assert(connect(fd, (struct sockaddr *)&address, sizeof(address)) == 0);
    for (size_t i = 0; i < 32; i++) { key[i] = (uint8_t)i; client_nonce[i] = (uint8_t)(0x40 + i); }
    EVP_EncodeBlock((unsigned char *)encoded_nonce, client_nonce, 32);
    snprintf(text, sizeof(text), "{\"version\":1,\"type\":\"auth.hello\",\"requestId\":\"%s\",\"payload\":{\"clientNonce\":\"%s\"}}", request_id, encoded_nonce);
    send_json(fd, text);
    struct json_object *reply = receive_json(fd);
    assert(strcmp(member_string(reply, "type"), "auth.challenge") == 0);
    struct json_object *payload;
    assert(json_object_object_get_ex(reply, "payload", &payload));
    const char *server_text = member_string(payload, "serverNonce");
    int decoded = EVP_DecodeBlock(decoded_nonce, (const unsigned char *)server_text,
        (int)strlen(server_text));
    assert(decoded == 33 && server_text[strlen(server_text) - 1] == '=');
    memcpy(server_nonce, decoded_nonce, 32);
    assert(rt_host_server_proof(key, client_nonce, server_nonce, proof) == 0);
    proof_hex(proof, hex);
    assert(strcmp(hex, member_string(payload, "serverProof")) == 0);
    json_object_put(reply);
    assert(rt_host_proof(key, client_nonce, server_nonce, proof) == 0);
    proof_hex(proof, hex);
    snprintf(text, sizeof(text), "{\"version\":1,\"type\":\"auth.proof\",\"requestId\":\"%s\",\"payload\":{\"proof\":\"%s\"}}", request_id, hex);
    send_json(fd, text);
    reply = receive_json(fd);
    assert(strcmp(member_string(reply, "type"), "auth.ok") == 0);
    json_object_put(reply);
    assert(rt_host_session_key(key, client_nonce, server_nonce, session_key) == 0);
    secure_active = true;
    snprintf(text, sizeof(text), "{\"version\":1,\"type\":\"node.discover\",\"requestId\":\"%s\"}", request_id);
    send_json(fd, text);
    reply = receive_json(fd);
    assert(strcmp(member_string(reply, "type"), "node.list") == 0);
    struct json_object *result, *nodes;
    assert(json_object_object_get_ex(reply, "result", &result));
    assert(json_object_object_get_ex(result, "nodes", &nodes));
    assert(json_object_array_length(nodes) == 1);
    json_object_put(reply);
    snprintf(text, sizeof(text), "{\"version\":1,\"type\":\"node.subscribe\",\"requestId\":\"%s\"}", request_id);
    send_json(fd, text);
    reply = receive_json(fd);
    assert(strcmp(member_string(reply, "type"), "node.subscribed") == 0);
    json_object_put(reply);
    snprintf(text, sizeof(text), "{\"version\":1,\"type\":\"serial.write\",\"requestId\":\"%s\",\"nodeId\":0}", request_id);
    send_json(fd, text);
    reply = receive_json(fd);
    assert(strcmp(member_string(reply, "type"), "request.error") == 0);
    struct json_object *remote_error;
    assert(json_object_object_get_ex(reply, "error", &remote_error));
    assert(strcmp(member_string(remote_error, "code"), "not_permitted") == 0);
    json_object_put(reply);
    snprintf(text, sizeof(text), "{\"version\":1,\"type\":\"node.discover\",\"requestId\":\"%s\"}", request_id);
    send_json(fd, text);
    reply = receive_json(fd);
    assert(strcmp(member_string(reply, "type"), "node.list") == 0);
    json_object_put(reply);
    const char *tampered_json = "{\"version\":1,\"type\":\"node.discover\",\"requestId\":\"123e4567-e89b-42d3-a456-426614174000\"}";
    uint8_t bad_body[256], bad_header[4];
    size_t bad_length;
    assert(rt_host_secure_wrap(session_key, false, outgoing_sequence + 1,
        (const uint8_t *)tampered_json, strlen(tampered_json),
        bad_body, sizeof(bad_body), &bad_length) == 0);
    bad_body[bad_length - 1] ^= 1;
    assert(rt_host_tcp_header(bad_length, bad_header) == 0);
    write_exact(fd, bad_header, 4);
    write_exact(fd, bad_body, bad_length);
    assert(read(fd, bad_header, 1) == 0);
    close(fd);
    return 0;
}

struct child_watch { struct uloop_process process; bool done; bool passed; };
static void child_exit(struct uloop_process *process, int status)
{
    struct child_watch *watch = container_of(process, struct child_watch, process);
    watch->done = true;
    watch->passed = WIFEXITED(status) && WEXITSTATUS(status) == 0;
    uloop_end();
}

static void timeout_cb(struct uloop_timeout *timer)
{
    (void)timer;
    uloop_end();
}

int main(void)
{
    struct rt_host_server *server = NULL;
    struct child_watch child = { .process.cb = child_exit };
    struct uloop_timeout timer = { .cb = timeout_cb };
    uint16_t port = (uint16_t)(40000 + getpid() % 20000);
    assert(uloop_init() == 0);
    for (unsigned i = 0; i < 100 && !server; i++) server = rt_host_server_start(port++, "", "test", request_cb, NULL);
    assert(server);
    port--;
    child.process.pid = fork();
    assert(child.process.pid >= 0);
    if (child.process.pid == 0) _exit(client_flow(port));
    assert(uloop_process_add(&child.process) == 0);
    uloop_timeout_set(&timer, 3000);
    uloop_run();
    uloop_timeout_cancel(&timer);
    assert(child.done && child.passed);
    rt_host_server_stop(server);
    uloop_done();
    return 0;
}
