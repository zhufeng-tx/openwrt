/* SPDX-License-Identifier: GPL-2.0-only */
#include "../src/host/rt_host_framing.h"
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>

int main(void)
{
    const uint8_t message[] = {'{', '"', 'x', '"', ':', '0', '}', 0, 1, 2};
    uint8_t frame[64], decoded[64], header[4];
    size_t frame_len = 0, decoded_len = 0;

    assert(rt_host_uart_encode(message, sizeof(message), frame, sizeof(frame), &frame_len) == 0);
    assert(frame_len > sizeof(message) && frame[frame_len - 1] == 0);
    assert(rt_host_uart_decode(frame, frame_len - 1, decoded, sizeof(decoded), &decoded_len) == 0);
    assert(decoded_len == sizeof(message));
    assert(memcmp(message, decoded, sizeof(message)) == 0);
    frame[2] ^= 1;
    assert(rt_host_uart_decode(frame, frame_len - 1, decoded, sizeof(decoded), &decoded_len) == -EBADMSG);
    frame[2] ^= 1;
    assert(rt_host_uart_decode(frame, 0, decoded, sizeof(decoded), &decoded_len) == -EINVAL);
    assert(rt_host_uart_decode(frame, frame_len - 1, decoded, 3, &decoded_len) == -ENOSPC);

    assert(rt_host_tcp_header(0x12345, header) == 0);
    assert(rt_host_tcp_length(header) == 0x12345);
    assert(rt_host_tcp_header(0, header) == -EINVAL);

    uint8_t full_range[512], long_frame[600], long_decoded[520];
    size_t long_frame_len, long_decoded_len;
    for (size_t i = 0; i < sizeof(full_range); i++) full_range[i] = (uint8_t)i;
    assert(rt_host_uart_encode(full_range, sizeof(full_range), long_frame,
        sizeof(long_frame), &long_frame_len) == 0);
    assert(rt_host_uart_decode(long_frame, long_frame_len - 1, long_decoded,
        sizeof(long_decoded), &long_decoded_len) == 0);
    assert(long_decoded_len == sizeof(full_range));
    assert(memcmp(full_range, long_decoded, sizeof(full_range)) == 0);
    return 0;
}
