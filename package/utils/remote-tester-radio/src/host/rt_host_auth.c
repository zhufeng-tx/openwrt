/* SPDX-License-Identifier: GPL-2.0-only */
#include "rt_host_auth.h"
#include <errno.h>
#include <fcntl.h>
#include <mbedtls/md.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef RT_HOST_TEST_HOOKS
static int hex_digit(unsigned char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int rt_host_key_load(const char *path, uint8_t key[RT_HOST_KEY_BYTES])
{
    char encoded[RT_HOST_KEY_BYTES * 2 + 2];
    struct stat st;
    size_t length = 0;
    int fd;

    if (!path || !key) return -EINVAL;
    fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return -errno;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_uid != 0 ||
        (st.st_mode & 0077) != 0 || st.st_size < (off_t)(RT_HOST_KEY_BYTES * 2) ||
        st.st_size > (off_t)(RT_HOST_KEY_BYTES * 2 + 1)) {
        close(fd);
        return -EACCES;
    }
    while (length < (size_t)st.st_size) {
        ssize_t count = read(fd, encoded + length, (size_t)st.st_size - length);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) {
            int result = count == 0 ? -EIO : -errno;
            close(fd);
            return result;
        }
        length += (size_t)count;
    }
    close(fd);
    if (length == RT_HOST_KEY_BYTES * 2 + 1 && encoded[length - 1] == '\n') length--;
    if (length != RT_HOST_KEY_BYTES * 2) return -EINVAL;
    for (size_t i = 0; i < RT_HOST_KEY_BYTES; i++) {
        int high = hex_digit((unsigned char)encoded[i * 2]);
        int low = hex_digit((unsigned char)encoded[i * 2 + 1]);
        if (high < 0 || low < 0) {
            memset(key, 0, RT_HOST_KEY_BYTES);
            return -EINVAL;
        }
        key[i] = (uint8_t)((high << 4) | low);
    }
    return 0;
}
#endif

int rt_host_random_nonce(uint8_t nonce[RT_HOST_NONCE_BYTES])
{
    int fd;
    size_t used = 0;
    if (!nonce) return -EINVAL;
    fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -errno;
    while (used < RT_HOST_NONCE_BYTES) {
        ssize_t count = read(fd, nonce + used, RT_HOST_NONCE_BYTES - used);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) {
            int result = count == 0 ? -EIO : -errno;
            close(fd);
            return result;
        }
        used += (size_t)count;
    }
    close(fd);
    return 0;
}

int rt_hmac_sha256(const uint8_t key[RT_HOST_KEY_BYTES],
    const uint8_t *message, size_t message_length,
    uint8_t digest[RT_HOST_PROOF_BYTES])
{
    const mbedtls_md_info_t *md;
    if (!key || !message || !digest) return -EINVAL;
    md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!md) return -ENOSYS;
    return mbedtls_md_hmac(md, key, RT_HOST_KEY_BYTES,
        message, message_length, digest) ? -EIO : 0;
}

static int proof_with_label(const uint8_t key[RT_HOST_KEY_BYTES],
    const uint8_t client_nonce[RT_HOST_NONCE_BYTES],
    const uint8_t server_nonce[RT_HOST_NONCE_BYTES],
    const uint8_t *label, size_t label_length,
    uint8_t proof[RT_HOST_PROOF_BYTES])
{
    uint8_t message[48 + 2 * RT_HOST_NONCE_BYTES];
    if (!key || !client_nonce || !server_nonce || !proof || label_length > 48)
        return -EINVAL;
    memcpy(message, label, label_length);
    memcpy(message + label_length, client_nonce, RT_HOST_NONCE_BYTES);
    memcpy(message + label_length + RT_HOST_NONCE_BYTES, server_nonce, RT_HOST_NONCE_BYTES);
    return rt_hmac_sha256(key, message,
        label_length + 2 * RT_HOST_NONCE_BYTES, proof);
}

int rt_host_proof(const uint8_t key[RT_HOST_KEY_BYTES],
    const uint8_t client_nonce[RT_HOST_NONCE_BYTES],
    const uint8_t server_nonce[RT_HOST_NONCE_BYTES],
    uint8_t proof[RT_HOST_PROOF_BYTES])
{
    static const uint8_t label[] = "remoteTester-host-v1";
    return proof_with_label(key, client_nonce, server_nonce,
        label, sizeof(label), proof);
}

int rt_host_server_proof(const uint8_t key[RT_HOST_KEY_BYTES],
    const uint8_t client_nonce[RT_HOST_NONCE_BYTES],
    const uint8_t server_nonce[RT_HOST_NONCE_BYTES],
    uint8_t proof[RT_HOST_PROOF_BYTES])
{
    static const uint8_t label[] = "remoteTester-host-server-v1";
    return proof_with_label(key, client_nonce, server_nonce,
        label, sizeof(label), proof);
}

int rt_host_proof_verify(const uint8_t expected[RT_HOST_PROOF_BYTES],
    const uint8_t actual[RT_HOST_PROOF_BYTES])
{
    uint8_t difference = 0;
    if (!expected || !actual) return -EINVAL;
    for (size_t i = 0; i < RT_HOST_PROOF_BYTES; i++)
        difference |= expected[i] ^ actual[i];
    return difference ? -EACCES : 0;
}
