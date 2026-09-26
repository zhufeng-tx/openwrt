/* SPDX-License-Identifier: GPL-2.0-only */
#include "../src/rt_ip_offload.h"
#include <assert.h>
#include <errno.h>
#include <libubox/uloop.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

struct test_context {
    struct rt_ip_client *client;
    uint8_t eui[8];
    uint8_t key[32];
    bool sent;
    bool healthy;
    bool acked;
    bool disconnected_after_ack;
    bool initial_unhealthy;
    unsigned healthy_count;
    unsigned state_callbacks;
    unsigned received;
};

static int lookup(void *opaque, const uint8_t eui[8], uint8_t key[32], uint8_t *node_id)
{
    struct test_context *test = opaque;
    if (memcmp(eui, test->eui, 8)) return -EACCES;
    memcpy(key, test->key, 32);
    *node_id = 1;
    return 0;
}

static int receive_block(void *opaque, uint8_t node_id,
    const struct rt_ip_block *block, uint32_t *next_offset)
{
    struct test_context *test = opaque;
    assert(node_id == 1);
    assert(block->stream_id == 7 && block->block_id == 3);
    assert(block->raw_offset == 100 && block->raw_length == 5);
    assert(block->codec == 0 && block->encoded_length == 5);
    assert(memcmp(block->encoded, "hello", 5) == 0);
    *next_offset = 105;
    test->received++;
    return 0;
}

static void acknowledge(void *opaque, uint32_t stream_id,
    uint16_t block_id, uint32_t next_offset)
{
    struct test_context *test = opaque;
    assert(stream_id == 7 && block_id == 3 && next_offset == 105);
    test->acked = true;
#ifndef TEST_IP_IDLE
    uloop_end();
#endif
}

static void state_changed(void *opaque, bool healthy)
{
    struct test_context *test = opaque;
    if (test->state_callbacks++ == 0 && !healthy) test->initial_unhealthy = true;
    test->healthy = healthy;
    if (healthy) test->healthy_count++;
    else if (test->acked) test->disconnected_after_ack = true;
#ifdef TEST_IP_IDLE
    if (healthy && test->healthy_count >= 2 && test->disconnected_after_ack)
        uloop_end();
#endif
    if (healthy && !test->sent) {
        const struct rt_ip_block block = {
            .stream_id = 7, .block_id = 3, .raw_offset = 100,
            .raw_length = 5, .codec = 0,
            .encoded = (const uint8_t *)"hello", .encoded_length = 5,
        };
        test->sent = true;
        assert(rt_ip_client_send(test->client, &block) == 0);
    }
}

static void timeout_cb(struct uloop_timeout *timer)
{
    (void)timer;
    uloop_end();
}

int main(void)
{
    struct test_context test = {};
    struct rt_ip_server *server = NULL;
    struct uloop_timeout timeout = { .cb = timeout_cb };
    uint16_t port = (uint16_t)(40000 + getpid() % 20000);
    assert(uloop_init() == 0);
    for (unsigned attempt = 0; attempt < 100 && !server; attempt++)
        server = rt_ip_server_start(port++, lookup, receive_block, &test);
    assert(server);
    port--;
    for (size_t i = 0; i < sizeof(test.eui); i++) test.eui[i] = (uint8_t)(0x10 + i);
    for (size_t i = 0; i < sizeof(test.key); i++) test.key[i] = (uint8_t)i;
    test.client = rt_ip_client_start("127.0.0.1", port, test.eui, test.key,
        acknowledge, state_changed, &test);
    assert(test.client);
    uloop_timeout_set(&timeout, 3000);
    uloop_run();
    uloop_timeout_cancel(&timeout);
    assert(test.initial_unhealthy && test.sent && test.acked && test.received == 1);
#ifdef TEST_IP_IDLE
    assert(test.disconnected_after_ack && test.healthy_count >= 2);
#endif
    rt_ip_client_stop(test.client);
    rt_ip_server_stop(server);
    uloop_done();
    return 0;
}
