#include "types.h"
#include <string.h>
#include <arpa/inet.h>
#include <endian.h>

int build_manet2(uint8_t *buf, int buf_size, uint32_t seq_num,
                 usec_t send_ts_us, uint16_t universe, int pkt_size)
{
    const int total = (pkt_size > 0) ? pkt_size : 1000;
    if (total < 20) return -1;
    if (buf_size < total + (int)sizeof(wltp_trailer_t)) return -1;

    memset(buf, 0, (size_t)total);

    /* Plausible MA-Net2 header */
    /* Magic: "MANET" */
    memcpy(buf, "MANET", 5);
    /* Version */
    buf[5] = 0x02;
    /* Packet type: DMX data */
    buf[6] = 0x00; buf[7] = 0x01;
    /* Sequence number (big-endian) */
    buf[8] = (uint8_t)((seq_num >> 24) & 0xFF);
    buf[9] = (uint8_t)((seq_num >> 16) & 0xFF);
    buf[10] = (uint8_t)((seq_num >> 8) & 0xFF);
    buf[11] = (uint8_t)(seq_num & 0xFF);
    /* Session ID */
    buf[12] = 0x01;
    /* Universe */
    buf[13] = (uint8_t)(universe & 0xFF);
    /* Data length (big-endian) */
    uint16_t dlen = (uint16_t)(total - 20);
    buf[14] = (uint8_t)((dlen >> 8) & 0xFF);
    buf[15] = (uint8_t)(dlen & 0xFF);

    /* Fill payload with test pattern */
    for (int i = 20; i < total; i++)
        buf[i] = (uint8_t)((seq_num + (uint32_t)i) & 0xFF);

    /* WLTP trailer */
    wltp_trailer_t t;
    t.magic      = htonl(WLTP_MAGIC);
    t.seq_num    = htonl(seq_num);
    t.send_ts_us = htobe64(send_ts_us);
    t.proto_id   = htons(PROTO_MANET2);
    t.flags      = 0;
    memcpy(buf + total, &t, sizeof(t));

    return total + (int)sizeof(wltp_trailer_t);
}
