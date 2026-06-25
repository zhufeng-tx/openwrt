#include "types.h"
#include <string.h>
#include <arpa/inet.h>
#include <endian.h>

int build_citp(uint8_t *buf, int buf_size, uint32_t seq_num,
               usec_t send_ts_us, uint16_t universe, int pkt_size)
{
    (void)universe;
    const int total = (pkt_size > 0) ? pkt_size : 512;
    if (total < 33) return -1;
    if (buf_size < total + (int)sizeof(wltp_trailer_t)) return -1;

    memset(buf, 0, (size_t)total);

    /* CITP Header */
    /* Cookie: "CITP" */
    buf[0] = 0x43; buf[1] = 0x49; buf[2] = 0x54; buf[3] = 0x50;
    /* Version major.minor */
    buf[4] = 0x01; buf[5] = 0x00;
    /* Request/Response Index (little-endian) */
    uint16_t idx = (uint16_t)(seq_num & 0xFFFF);
    buf[6] = (uint8_t)(idx & 0xFF);
    buf[7] = (uint8_t)((idx >> 8) & 0xFF);
    /* Message Size (little-endian, total packet size) */
    buf[8]  = (uint8_t)(total & 0xFF);
    buf[9]  = (uint8_t)((total >> 8) & 0xFF);
    buf[10] = (uint8_t)((total >> 16) & 0xFF);
    buf[11] = (uint8_t)((total >> 24) & 0xFF);
    /* Message Part Count */
    buf[12] = 0x01; buf[13] = 0x00;
    /* Message Part */
    buf[14] = 0x00; buf[15] = 0x00;
    /* Content Type: "PINF" */
    buf[16] = 0x50; buf[17] = 0x49; buf[18] = 0x4E; buf[19] = 0x46;

    /* PINF Name sub-layer */
    buf[20] = 0x4E; buf[21] = 0x61;  /* "Na" */
    buf[22] = 0x6D; buf[23] = 0x65;  /* "me" */
    /* Name string: "WLTP Test" */
    memcpy(buf + 24, "WLTP Test", 9);

    /* Fill remaining with test pattern */
    for (int i = 33; i < total; i++)
        buf[i] = (uint8_t)((seq_num + (uint32_t)i) & 0xFF);

    /* WLTP trailer */
    wltp_trailer_t t;
    t.magic      = htonl(WLTP_MAGIC);
    t.seq_num    = htonl(seq_num);
    t.send_ts_us = htobe64(send_ts_us);
    t.proto_id   = htons(PROTO_CITP);
    t.flags      = 0;
    memcpy(buf + total, &t, sizeof(t));

    return total + (int)sizeof(wltp_trailer_t);
}
