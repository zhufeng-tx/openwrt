/* SPDX-License-Identifier: GPL-2.0-only */
#include "../src/host/rt_host_secure.h"
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>

int main(void)
{
    uint8_t psk[32], client_nonce[32], server_nonce[32], key[32];
    uint8_t body[128], plain[128];
    size_t body_length, plain_length;
    const uint8_t json[] = "{\"type\":\"node.discover\"}";
    for (size_t i = 0; i < 32; i++) {
        psk[i] = (uint8_t)i;
        client_nonce[i] = (uint8_t)(i + 32);
        server_nonce[i] = (uint8_t)(i + 64);
    }
    assert(rt_host_session_key(psk, client_nonce, server_nonce, key) == 0);
    assert(rt_host_secure_wrap(key, false, 1, json, sizeof(json) - 1,
        body, sizeof(body), &body_length) == 0);
    assert(body_length == sizeof(json) - 1 + RT_HOST_SECURE_TRAILER_BYTES);
    assert(rt_host_secure_unwrap(key, false, 1, body, body_length,
        plain, sizeof(plain), &plain_length) == 0);
    assert(plain_length == sizeof(json) - 1 &&
        memcmp(plain, json, plain_length) == 0);
    assert(rt_host_secure_unwrap(key, false, 2, body, body_length,
        plain, sizeof(plain), &plain_length) == -EBADMSG);
    assert(rt_host_secure_unwrap(key, true, 1, body, body_length,
        plain, sizeof(plain), &plain_length) == -EACCES);
    body[0] ^= 1;
    assert(rt_host_secure_unwrap(key, false, 1, body, body_length,
        plain, sizeof(plain), &plain_length) == -EACCES);
    return 0;
}
