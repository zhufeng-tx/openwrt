/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef REMOTE_TESTER_HOST_AUTH_H
#define REMOTE_TESTER_HOST_AUTH_H

#include <stddef.h>
#include <stdint.h>

#define RT_HOST_KEY_BYTES 32U
#define RT_HOST_NONCE_BYTES 32U
#define RT_HOST_PROOF_BYTES 32U

/* The key file contains exactly 64 hex digits and an optional final newline. */
int rt_host_key_load(const char *path, uint8_t key[RT_HOST_KEY_BYTES]);
int rt_host_random_nonce(uint8_t nonce[RT_HOST_NONCE_BYTES]);
int rt_hmac_sha256(const uint8_t key[RT_HOST_KEY_BYTES],
    const uint8_t *message, size_t message_length,
    uint8_t digest[RT_HOST_PROOF_BYTES]);
int rt_host_proof(const uint8_t key[RT_HOST_KEY_BYTES],
    const uint8_t client_nonce[RT_HOST_NONCE_BYTES],
    const uint8_t server_nonce[RT_HOST_NONCE_BYTES],
    uint8_t proof[RT_HOST_PROOF_BYTES]);
int rt_host_server_proof(const uint8_t key[RT_HOST_KEY_BYTES],
    const uint8_t client_nonce[RT_HOST_NONCE_BYTES],
    const uint8_t server_nonce[RT_HOST_NONCE_BYTES],
    uint8_t proof[RT_HOST_PROOF_BYTES]);
int rt_host_proof_verify(const uint8_t expected[RT_HOST_PROOF_BYTES],
    const uint8_t actual[RT_HOST_PROOF_BYTES]);

#endif
