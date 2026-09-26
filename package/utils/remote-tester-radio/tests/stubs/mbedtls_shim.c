/* SPDX-License-Identifier: GPL-2.0-only */
#include <mbedtls/base64.h>
#include <mbedtls/md.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <stddef.h>
#include <string.h>

static const mbedtls_md_info_t sha256_info = { MBEDTLS_MD_SHA256 };

const mbedtls_md_info_t *mbedtls_md_info_from_type(int type)
{
    return type == MBEDTLS_MD_SHA256 ? &sha256_info : NULL;
}

int mbedtls_md_hmac(const mbedtls_md_info_t *md, const unsigned char *key,
    size_t keylen, const unsigned char *input, size_t ilen,
    unsigned char *output)
{
    unsigned int length = 0;
    return md && HMAC(EVP_sha256(), key, (int)keylen, input, ilen,
        output, &length) && length == 32 ? 0 : -1;
}

int mbedtls_base64_encode(unsigned char *dst, size_t dlen, size_t *olen,
    const unsigned char *src, size_t slen)
{
    size_t needed = ((slen + 2) / 3) * 4;
    if (dlen < needed + 1) return -1;
    int length = EVP_EncodeBlock(dst, src, (int)slen);
    if (length < 0) return -1;
    *olen = (size_t)length;
    return 0;
}

int mbedtls_base64_decode(unsigned char *dst, size_t dlen, size_t *olen,
    const unsigned char *src, size_t slen)
{
    if (slen == 0 || slen % 4) return -1;
    size_t padding = (src[slen - 1] == '=') + (src[slen - 2] == '=');
    size_t decoded = slen / 4 * 3 - padding;
    if (dlen < decoded) return -1;
    unsigned char temporary[8192];
    if (slen / 4 * 3 > sizeof(temporary)) return -1;
    int length = EVP_DecodeBlock(temporary, src, (int)slen);
    if (length < 0) return -1;
    if (src[slen - 1] == '=') length--;
    if (src[slen - 2] == '=') length--;
    memcpy(dst, temporary, (size_t)length);
    *olen = (size_t)length;
    return 0;
}
