#include "types.h"
#include <string.h>
#include <arpa/inet.h>
#include <endian.h>

int build_sacn(uint8_t *buf, int buf_size, uint32_t seq_num,
               usec_t send_ts_us, uint16_t universe, int pkt_size)
{
    (void)pkt_size;
    const int total = 638;
    if (buf_size < total + (int)sizeof(wltp_trailer_t)) return -1;

    memset(buf, 0, (size_t)total);

    /* Root Layer Preamble */
    buf[0] = 0x00; buf[1] = 0x10;
    buf[2] = 0x00; buf[3] = 0x00;
    memcpy(buf + 4, "ASC-E1.17\0\0\0", 12);

    /* Root Flags & Length */
    uint16_t root_fl = 0x7000 | (uint16_t)(total - 16);
    buf[16] = (uint8_t)((root_fl >> 8) & 0xFF);
    buf[17] = (uint8_t)(root_fl & 0xFF);

    /* Root Vector: E1.31 Data */
    buf[18] = 0x00; buf[19] = 0x00; buf[20] = 0x00; buf[21] = 0x04;

    /* CID */
    buf[22] = 0x57; buf[23] = 0x4C; buf[24] = 0x54; buf[25] = 0x50;

    /* Framing Layer */
    uint16_t frame_fl = 0x7000 | (uint16_t)(total - 38);
    buf[38] = (uint8_t)((frame_fl >> 8) & 0xFF);
    buf[39] = (uint8_t)(frame_fl & 0xFF);

    /* Framing Vector */
    buf[40] = 0x00; buf[41] = 0x00; buf[42] = 0x00; buf[43] = 0x02;

    /* Source Name */
    memcpy(buf + 44, "WLTP Test Source", 16);

    /* Priority */
    buf[108] = 100;

    /* Sequence Number */
    buf[111] = (uint8_t)(seq_num & 0xFF);

    /* Universe (big-endian) */
    buf[113] = (uint8_t)((universe >> 8) & 0xFF);
    buf[114] = (uint8_t)(universe & 0xFF);

    /* DMP Layer */
    uint16_t dmp_fl = 0x7000 | (uint16_t)(total - 115);
    buf[115] = (uint8_t)((dmp_fl >> 8) & 0xFF);
    buf[116] = (uint8_t)(dmp_fl & 0xFF);

    buf[117] = 0x02;  /* DMP Vector */
    buf[118] = 0xA1;  /* Address/Data Type */
    buf[119] = 0x00; buf[120] = 0x00;  /* First Property Address */
    buf[121] = 0x00; buf[122] = 0x01;  /* Address Increment */
    buf[123] = 0x02; buf[124] = 0x01;  /* Property Value Count (513) */

    /* Start code + 512 DMX values */
    buf[125] = 0x00;
    for (int i = 0; i < 512; i++)
        buf[126 + i] = (uint8_t)((seq_num + (uint32_t)i) & 0xFF);

    /* WLTP trailer */
    wltp_trailer_t t;
    t.magic      = htonl(WLTP_MAGIC);
    t.seq_num    = htonl(seq_num);
    t.send_ts_us = htobe64(send_ts_us);
    t.proto_id   = htons(PROTO_SACN);
    t.flags      = 0;
    memcpy(buf + total, &t, sizeof(t));

    return total + (int)sizeof(wltp_trailer_t);
}
