#include "types.h"
#include <string.h>
#include <arpa/inet.h>
#include <endian.h>

int build_klingnet(uint8_t *buf, int buf_size, uint32_t seq_num,
                   usec_t send_ts_us, uint16_t universe, int pkt_size)
{
    const int total = (pkt_size > 0) ? pkt_size : 512;
    if (total < 16) return -1;
    if (buf_size < total + (int)sizeof(wltp_trailer_t)) return -1;

    memset(buf, 0, (size_t)total);

    /* Plausible Kling-Net header */
    /* Magic identifier */
    buf[0] = 0x4B; buf[1] = 0x4C;  /* "KL" */
    buf[2] = 0x49; buf[3] = 0x4E;  /* "IN" */
    /* Protocol version */
    buf[4] = 0x01;
    /* Packet type: pixel data */
    buf[5] = 0x01;
    /* Sequence number */
    buf[6] = (uint8_t)((seq_num >> 8) & 0xFF);
    buf[7] = (uint8_t)(seq_num & 0xFF);
    /* Device ID */
    buf[8] = 0x00; buf[9] = 0x01;
    /* Universe */
    buf[10] = (uint8_t)((universe >> 8) & 0xFF);
    buf[11] = (uint8_t)(universe & 0xFF);
    /* Data length */
    uint16_t dlen = (uint16_t)(total - 16);
    buf[12] = (uint8_t)((dlen >> 8) & 0xFF);
    buf[13] = (uint8_t)(dlen & 0xFF);

    /* Fill pixel data with test pattern (RGB triplets) */
    for (int i = 16; i < total; i++)
        buf[i] = (uint8_t)((seq_num + (uint32_t)i) & 0xFF);

    /* WLTP trailer */
    wltp_trailer_t t;
    t.magic      = htonl(WLTP_MAGIC);
    t.seq_num    = htonl(seq_num);
    t.send_ts_us = htobe64(send_ts_us);
    t.proto_id   = htons(PROTO_KLINGNET);
    t.flags      = 0;
    memcpy(buf + total, &t, sizeof(t));

    return total + (int)sizeof(wltp_trailer_t);
}
