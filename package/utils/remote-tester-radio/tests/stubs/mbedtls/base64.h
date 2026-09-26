/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef REMOTE_TESTER_TEST_MBEDTLS_BASE64_H
#define REMOTE_TESTER_TEST_MBEDTLS_BASE64_H
#include <stddef.h>
int mbedtls_base64_decode(unsigned char *dst, size_t dlen, size_t *olen,
    const unsigned char *src, size_t slen);
int mbedtls_base64_encode(unsigned char *dst, size_t dlen, size_t *olen,
    const unsigned char *src, size_t slen);
#endif
