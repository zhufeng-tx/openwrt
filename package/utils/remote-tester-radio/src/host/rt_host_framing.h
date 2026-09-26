/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef REMOTE_TESTER_HOST_FRAMING_H
#define REMOTE_TESTER_HOST_FRAMING_H

#include <stddef.h>
#include <stdint.h>

/* UART: COBS(JSON || CRC32-IEEE(JSON), big-endian) || 0x00. */
int rt_host_uart_encode(const uint8_t *json, size_t json_len,
    uint8_t *frame, size_t frame_capacity, size_t *frame_len);
/* frame excludes the terminating zero; json may alias neither frame nor scratch. */
int rt_host_uart_decode(const uint8_t *frame, size_t frame_len,
    uint8_t *json, size_t json_capacity, size_t *json_len);

/* TCP: uint32 big-endian byte length followed by unmodified JSON. */
int rt_host_tcp_header(size_t json_len, uint8_t header[4]);
uint32_t rt_host_tcp_length(const uint8_t header[4]);

#endif
