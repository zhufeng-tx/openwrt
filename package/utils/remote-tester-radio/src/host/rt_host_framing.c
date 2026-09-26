/* SPDX-License-Identifier: GPL-2.0-only */
#include "rt_host_framing.h"
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

static uint32_t crc32_ieee(const uint8_t *data, size_t length)
{
    uint32_t crc = UINT32_C(0xffffffff);
    for (size_t i = 0; i < length; i++) {
        crc ^= data[i];
        for (unsigned bit = 0; bit < 8; bit++)
            crc = (crc >> 1) ^ ((crc & 1) ? UINT32_C(0xedb88320) : 0);
    }
    return ~crc;
}

int rt_host_uart_encode(const uint8_t *json, size_t json_len,
    uint8_t *frame, size_t frame_capacity, size_t *frame_len)
{
    uint8_t *body;
    uint32_t crc;
    size_t body_len, read_pos = 0, write_pos = 1, code_pos = 0;
    uint8_t code = 1;

    if (!json || !frame || !frame_len || json_len > SIZE_MAX - 4)
        return -EINVAL;
    body_len = json_len + 4;
    if (frame_capacity < body_len + body_len / 254 + 2)
        return -ENOSPC;
    body = malloc(body_len);
    if (!body) return -ENOMEM;
    memcpy(body, json, json_len);
    crc = crc32_ieee(json, json_len);
    body[json_len] = (uint8_t)(crc >> 24);
    body[json_len + 1] = (uint8_t)(crc >> 16);
    body[json_len + 2] = (uint8_t)(crc >> 8);
    body[json_len + 3] = (uint8_t)crc;

    while (read_pos < body_len) {
        uint8_t byte = body[read_pos++];
        if (byte == 0) {
            frame[code_pos] = code;
            code_pos = write_pos++;
            code = 1;
        } else {
            frame[write_pos++] = byte;
            code++;
            if (code == 255) {
                frame[code_pos] = code;
                code_pos = write_pos++;
                code = 1;
            }
        }
    }
    frame[code_pos] = code;
    frame[write_pos++] = 0;
    *frame_len = write_pos;
    free(body);
    return 0;
}

int rt_host_uart_decode(const uint8_t *frame, size_t frame_len,
    uint8_t *json, size_t json_capacity, size_t *json_len)
{
    size_t read_pos = 0, write_pos = 0;
    uint32_t expected, actual;
    if (!frame || !json || !json_len || frame_len == 0)
        return -EINVAL;
    while (read_pos < frame_len) {
        uint8_t code = frame[read_pos++];
        if (code == 0 || (size_t)(code - 1) > frame_len - read_pos)
            return -EBADMSG;
        if ((size_t)(code - 1) > json_capacity - write_pos)
            return -ENOSPC;
        for (unsigned i = 1; i < code; i++) {
            if (frame[read_pos] == 0) return -EBADMSG;
            json[write_pos++] = frame[read_pos++];
        }
        if (code != 255 && read_pos < frame_len) {
            if (write_pos >= json_capacity) return -ENOSPC;
            json[write_pos++] = 0;
        }
    }
    if (write_pos < 4) return -EBADMSG;
    write_pos -= 4;
    expected = ((uint32_t)json[write_pos] << 24) |
        ((uint32_t)json[write_pos + 1] << 16) |
        ((uint32_t)json[write_pos + 2] << 8) | json[write_pos + 3];
    actual = crc32_ieee(json, write_pos);
    if (expected != actual) return -EBADMSG;
    *json_len = write_pos;
    return 0;
}

int rt_host_tcp_header(size_t json_len, uint8_t header[4])
{
    if (!header || json_len == 0 || json_len > UINT32_MAX) return -EINVAL;
    header[0] = (uint8_t)(json_len >> 24);
    header[1] = (uint8_t)(json_len >> 16);
    header[2] = (uint8_t)(json_len >> 8);
    header[3] = (uint8_t)json_len;
    return 0;
}

uint32_t rt_host_tcp_length(const uint8_t header[4])
{
    return ((uint32_t)header[0] << 24) | ((uint32_t)header[1] << 16) |
        ((uint32_t)header[2] << 8) | header[3];
}
