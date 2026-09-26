/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef REMOTE_TESTER_IP_OFFLOAD_H
#define REMOTE_TESTER_IP_OFFLOAD_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define RT_IP_EUI_BYTES 8U
#define RT_IP_KEY_BYTES 32U
#define RT_IP_BLOCK_MAX 4096U

struct rt_ip_server;
struct rt_ip_client;

struct rt_ip_block {
    uint32_t stream_id;
    uint16_t block_id;
    uint32_t raw_offset;
    uint16_t raw_length;
    uint8_t codec;               /* 0 raw, 1 independent raw DEFLATE */
    const uint8_t *encoded;
    size_t encoded_length;
};

typedef int (*rt_ip_lookup_cb)(void *context, const uint8_t eui[RT_IP_EUI_BYTES],
    uint8_t key[RT_IP_KEY_BYTES], uint8_t *node_id);
/* Return 0 only after the block has been accepted for controller delivery. */
typedef int (*rt_ip_receive_cb)(void *context, uint8_t node_id,
    const struct rt_ip_block *block, uint32_t *next_offset);
typedef void (*rt_ip_ack_cb)(void *context, uint32_t stream_id,
    uint16_t block_id, uint32_t next_offset);
typedef void (*rt_ip_state_cb)(void *context, bool healthy);

struct rt_ip_server *rt_ip_server_start(uint16_t port,
    rt_ip_lookup_cb lookup, rt_ip_receive_cb receive, void *context);
void rt_ip_server_stop(struct rt_ip_server *server);

struct rt_ip_client *rt_ip_client_start(const char *controller_ipv4, uint16_t port,
    const uint8_t eui[RT_IP_EUI_BYTES], const uint8_t key[RT_IP_KEY_BYTES],
    rt_ip_ack_cb acknowledge, rt_ip_state_cb state, void *context);
void rt_ip_client_stop(struct rt_ip_client *client);
/* One block remains pending until an authenticated ACK; duplicate calls return -EBUSY. */
int rt_ip_client_send(struct rt_ip_client *client, const struct rt_ip_block *block);
void rt_ip_client_cancel_pending(struct rt_ip_client *client, uint32_t stream_id,
    uint16_t block_id);
bool rt_ip_client_healthy(const struct rt_ip_client *client);

#endif
