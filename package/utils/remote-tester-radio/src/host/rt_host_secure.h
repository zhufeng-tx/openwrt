/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef REMOTE_TESTER_HOST_SECURE_H
#define REMOTE_TESTER_HOST_SECURE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define RT_HOST_SECURE_TRAILER_BYTES 24U

int rt_host_session_key(const uint8_t psk[32], const uint8_t client_nonce[32],
    const uint8_t server_nonce[32], uint8_t session_key[32]);
/* Plain JSON is followed by an 8-byte BE sequence and a 16-byte HMAC tag. */
int rt_host_secure_wrap(const uint8_t session_key[32], bool server_to_client,
    uint64_t sequence, const uint8_t *json, size_t json_length,
    uint8_t *body, size_t body_capacity, size_t *body_length);
int rt_host_secure_unwrap(const uint8_t session_key[32], bool server_to_client,
    uint64_t expected_sequence, const uint8_t *body, size_t body_length,
    uint8_t *json, size_t json_capacity, size_t *json_length);

#endif
