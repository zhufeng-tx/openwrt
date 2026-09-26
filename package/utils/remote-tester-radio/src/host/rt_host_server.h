/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef REMOTE_TESTER_HOST_SERVER_H
#define REMOTE_TESTER_HOST_SERVER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct blob_attr;
struct blob_buf;
struct rt_host_server;

/* The callback adds members to the already-open result table. */
typedef int (*rt_host_request_cb)(void *context, const char *type,
    const char *request_id, uint8_t node_id, struct blob_attr *payload,
    struct blob_buf *result);

struct rt_host_server *rt_host_server_start(uint16_t tcp_port,
    const char *uart_device, const char *key_file,
    rt_host_request_cb callback, void *context);
void rt_host_server_stop(struct rt_host_server *server);
/* JSON must be a complete version-1 event object, at most 8192 bytes. */
int rt_host_server_publish(struct rt_host_server *server, const char *json);
bool rt_host_server_has_subscriber(const struct rt_host_server *server);

#ifdef RT_HOST_TEST_HOOKS
/* Inject an unterminated UART output prefix to test session resynchronization. */
int rt_host_server_test_emit_uart_prefix(struct rt_host_server *server,
    const uint8_t *prefix, size_t length);
#endif

#endif
