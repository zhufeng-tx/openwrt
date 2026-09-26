/* SPDX-License-Identifier: GPL-2.0-only */
#include "rt_host_secure.h"
#include "rt_host_auth.h"
#include <errno.h>
#include <stdint.h>
#include <string.h>

static void put_u64(uint8_t *out, uint64_t value)
{
    for (unsigned i = 0; i < 8; i++) out[i] = (uint8_t)(value >> (56U - i * 8U));
}

static uint64_t get_u64(const uint8_t *in)
{
    uint64_t value = 0;
    for (unsigned i = 0; i < 8; i++) value = (value << 8) | in[i];
    return value;
}

int rt_host_session_key(const uint8_t psk[32], const uint8_t client_nonce[32],
    const uint8_t server_nonce[32], uint8_t session_key[32])
{
    static const uint8_t label[] = "remoteTester-host-session-v1";
    uint8_t message[sizeof(label) + 64];
    if (!psk || !client_nonce || !server_nonce || !session_key) return -EINVAL;
    memcpy(message, label, sizeof(label));
    memcpy(message + sizeof(label), client_nonce, 32);
    memcpy(message + sizeof(label) + 32, server_nonce, 32);
    return rt_hmac_sha256(psk, message, sizeof(message), session_key);
}

static int frame_tag(const uint8_t session_key[32], bool server_to_client,
    uint64_t sequence, const uint8_t *json, size_t json_length, uint8_t tag[16])
{
    static const uint8_t to_server[] = "c2s";
    static const uint8_t to_client[] = "s2c";
    const uint8_t *direction = server_to_client ? to_client : to_server;
    uint8_t message[4 + 8 + 8192], digest[32];
    if (!session_key || !json || !sequence || json_length > 8192) return -EINVAL;
    memcpy(message, direction, 4);
    put_u64(message + 4, sequence);
    memcpy(message + 12, json, json_length);
    int error = rt_hmac_sha256(session_key, message, 12 + json_length, digest);
    if (!error) memcpy(tag, digest, 16);
    memset(digest, 0, sizeof(digest));
    return error;
}

int rt_host_secure_wrap(const uint8_t session_key[32], bool server_to_client,
    uint64_t sequence, const uint8_t *json, size_t json_length,
    uint8_t *body, size_t body_capacity, size_t *body_length)
{
    uint8_t tag[16];
    int error;
    if (!session_key || !json || !body || !body_length || !json_length ||
        json_length > 8192 || body_capacity < json_length + RT_HOST_SECURE_TRAILER_BYTES)
        return -EINVAL;
    error = frame_tag(session_key, server_to_client, sequence, json, json_length, tag);
    if (error) return error;
    memcpy(body, json, json_length);
    put_u64(body + json_length, sequence);
    memcpy(body + json_length + 8, tag, sizeof(tag));
    *body_length = json_length + RT_HOST_SECURE_TRAILER_BYTES;
    return 0;
}

int rt_host_secure_unwrap(const uint8_t session_key[32], bool server_to_client,
    uint64_t expected_sequence, const uint8_t *body, size_t body_length,
    uint8_t *json, size_t json_capacity, size_t *json_length)
{
    uint8_t expected_tag[16], difference = 0;
    size_t length;
    int error;
    if (!session_key || !body || !json || !json_length || !expected_sequence ||
        body_length <= RT_HOST_SECURE_TRAILER_BYTES) return -EINVAL;
    length = body_length - RT_HOST_SECURE_TRAILER_BYTES;
    if (length > json_capacity || length > 8192 ||
        get_u64(body + length) != expected_sequence) return -EBADMSG;
    error = frame_tag(session_key, server_to_client, expected_sequence,
        body, length, expected_tag);
    if (error) return error;
    for (size_t i = 0; i < sizeof(expected_tag); i++)
        difference |= expected_tag[i] ^ body[length + 8 + i];
    if (difference) return -EACCES;
    memcpy(json, body, length);
    *json_length = length;
    return 0;
}
