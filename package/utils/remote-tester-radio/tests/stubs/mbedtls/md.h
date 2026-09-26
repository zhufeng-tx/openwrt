/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef REMOTE_TESTER_TEST_MBEDTLS_MD_H
#define REMOTE_TESTER_TEST_MBEDTLS_MD_H
#include <stddef.h>
#define MBEDTLS_MD_SHA256 6
typedef struct { int type; } mbedtls_md_info_t;
const mbedtls_md_info_t *mbedtls_md_info_from_type(int type);
int mbedtls_md_hmac(const mbedtls_md_info_t *md, const unsigned char *key,
    size_t keylen, const unsigned char *input, size_t ilen,
    unsigned char *output);
#endif
