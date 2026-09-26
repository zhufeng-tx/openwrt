/* SPDX-License-Identifier: GPL-2.0-only */
#include "../src/rt_command.h"
#include <assert.h>
#include <errno.h>
#include <arpa/inet.h>
#include <libubox/uloop.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

struct iperf_event_state {
    uint8_t uuid[RT_COMMAND_UUID_BYTES];
    int status;
    bool done;
};

static void iperf_event(void *opaque,
    const uint8_t request_uuid[RT_COMMAND_UUID_BYTES], int status)
{
    struct iperf_event_state *state = opaque;
    memcpy(state->uuid, request_uuid, RT_COMMAND_UUID_BYTES);
    state->status = status;
    state->done = true;
    uloop_end();
}

static void iperf_timeout(struct uloop_timeout *timer)
{
    (void)timer;
    uloop_end();
}

/* This test exercises command framing and replay without decoding host base64. */
int mbedtls_base64_decode(unsigned char *dst, size_t dlen, size_t *olen,
    const unsigned char *src, size_t slen)
{
    (void)dst; (void)dlen; (void)olen; (void)src; (void)slen;
    return -1;
}

int main(void)
{
    static const char id[] = "123e4567-e89b-42d3-a456-426614174000";
    uint8_t uuid[16], encoded[200];
    char roundtrip[37];
    size_t encoded_len;
    struct rt_command write = { .kind = RT_COMMAND_UART_WRITE,
        .chunk_count = 1, .data_length = 3, .data = {'A', 'B', 'C'} };
    struct rt_command decoded;
    struct rt_command_result result, result_roundtrip;
    struct rt_command_agent *agent;
    int fds[2];
    char bytes[8];
    struct iperf_event_state event = { 0 };
    struct uloop_timeout timeout = { .cb = iperf_timeout };
    struct rt_command iperf_a = { .kind = RT_COMMAND_IPERF_START,
        .chunk_count = 1, .data_length = 29 };
    struct rt_command iperf_b;
    uint8_t test_a[RT_COMMAND_UUID_BYTES], test_b[RT_COMMAND_UUID_BYTES];

    assert(rt_command_uuid_parse(id, uuid) == 0);
    rt_command_uuid_format(uuid, roundtrip);
    assert(strcmp(id, roundtrip) == 0);
    assert(rt_command_uuid_parse("not-a-uuid", uuid) == -EINVAL);
    memcpy(write.request_uuid, uuid, 16);
    assert(rt_command_encode(&write, encoded, sizeof(encoded), &encoded_len) == 0);
    assert(rt_command_decode(encoded, encoded_len, &decoded) == 0);
    assert(decoded.kind == RT_COMMAND_UART_WRITE && decoded.data_length == 3);
    assert(memcmp(decoded.data, "ABC", 3) == 0);
    encoded[18] = 0;
    assert(rt_command_decode(encoded, encoded_len, &decoded) == -EINVAL);

    assert(pipe(fds) == 0);
    agent = rt_command_agent_start(fds[1], NULL, NULL);
    assert(agent);
    assert(rt_command_agent_execute(agent, &write, &result) == 0);
    assert(result.status == 0 && result.written == 3);
    assert(rt_command_agent_execute(agent, &write, &result) == 0);
    assert(result.status == 0 && result.written == 3);
    assert(read(fds[0], bytes, sizeof(bytes)) == 3);
    assert(memcmp(bytes, "ABC", 3) == 0);
    write.data[0] = 'X';
    assert(rt_command_agent_execute(agent, &write, &result) == 0);
    assert(result.status == EINVAL && result.written == 0);
    assert(rt_command_result_encode(&result, encoded, sizeof(encoded), &encoded_len) == 0);
    assert(rt_command_result_decode(encoded, encoded_len, &result_roundtrip) == 0);
    assert(result_roundtrip.status == EINVAL);
    rt_command_agent_stop(agent);
    close(fds[0]); close(fds[1]);

    assert(rt_command_uuid_parse("323e4567-e89b-42d3-a456-426614174000", test_a) == 0);
    assert(rt_command_uuid_parse("423e4567-e89b-42d3-a456-426614174000", test_b) == 0);
    memcpy(iperf_a.data, test_a, sizeof(test_a));
    assert(inet_pton(AF_INET, "127.0.0.1", iperf_a.data + 16) == 1);
    iperf_a.data[20] = 0x14; iperf_a.data[21] = 0x51;
    iperf_a.data[22] = 0; iperf_a.data[23] = 2;
    iperf_a.data[24] = 0;
    memcpy(iperf_a.request_uuid, uuid, sizeof(uuid));
    iperf_b = iperf_a;
    memcpy(iperf_b.data, test_b, sizeof(test_b));
    iperf_b.request_uuid[0] ^= 0x80;
    assert(pipe(fds) == 0);
    assert(uloop_init() == 0);
    agent = rt_command_agent_start(fds[1], iperf_event, &event);
    assert(agent);
    assert(rt_command_agent_execute(agent, &iperf_a, &result) == 0);
    assert(result.status == 0 && rt_command_agent_iperf_active(agent));
    assert(rt_command_agent_execute(agent, &iperf_b, &result) == 0);
    assert(result.status == EBUSY && rt_command_agent_iperf_active(agent));
    assert(uloop_timeout_set(&timeout, 2000) == 0);
    uloop_run();
    uloop_timeout_cancel(&timeout);
    assert(event.done && event.status == 0);
    assert(!memcmp(event.uuid, test_a, sizeof(test_a)));
    assert(!rt_command_agent_iperf_active(agent));
    rt_command_agent_stop(agent);
    close(fds[0]); close(fds[1]);
    uloop_done();
    return 0;
}
