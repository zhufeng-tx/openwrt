/* SPDX-License-Identifier: GPL-2.0-only */
#include "../../src/host/rt_host_auth.h"
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

int rt_host_key_load(const char *path, uint8_t key[32])
{
    (void)path;
    for (size_t i = 0; i < 32; i++) key[i] = (uint8_t)i;
    return 0;
}

int rt_host_random_nonce(uint8_t nonce[32])
{
    for (size_t i = 0; i < 32; i++) nonce[i] = (uint8_t)(0xa0 + i);
    return 0;
}

int rt_hmac_sha256(const uint8_t key[32], const uint8_t *message,
    size_t message_length, uint8_t digest[32])
{
    unsigned length = 0;
    return HMAC(EVP_sha256(), key, 32, message, message_length,
        digest, &length) && length == 32 ? 0 : -1;
}

static int proof(const uint8_t key[32], const char *label,
    const uint8_t client_nonce[32], const uint8_t server_nonce[32],
    uint8_t result[32])
{
    uint8_t message[128];
    size_t label_length = strlen(label) + 1;
    memcpy(message, label, label_length);
    memcpy(message + label_length, client_nonce, 32);
    memcpy(message + label_length + 32, server_nonce, 32);
    return rt_hmac_sha256(key, message, label_length + 64, result);
}

int rt_host_proof(const uint8_t key[32], const uint8_t client_nonce[32],
    const uint8_t server_nonce[32], uint8_t result[32])
{
    return proof(key, "remoteTester-host-v1", client_nonce, server_nonce, result);
}

int rt_host_server_proof(const uint8_t key[32], const uint8_t client_nonce[32],
    const uint8_t server_nonce[32], uint8_t result[32])
{
    return proof(key, "remoteTester-host-server-v1", client_nonce, server_nonce, result);
}

int rt_host_proof_verify(const uint8_t expected[32], const uint8_t actual[32])
{
    uint8_t mismatch = 0;
    for (size_t i = 0; i < 32; i++) mismatch |= expected[i] ^ actual[i];
    return mismatch ? -1 : 0;
}
