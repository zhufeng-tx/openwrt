#include "types.h"
#include <string.h>
#include <arpa/inet.h>
#include <endian.h>

int build_psn(uint8_t *buf, int buf_size, uint32_t seq_num,
              usec_t send_ts_us, uint16_t universe, int pkt_size)
{
    (void)universe;
    const int total = (pkt_size > 0) ? pkt_size : 200;
    if (total < 36) return -1;
    if (buf_size < total + (int)sizeof(wltp_trailer_t)) return -1;

    memset(buf, 0, (size_t)total);

    /* PSN Data Header chunk */
    /* Chunk ID: 0x6756 (PSN) */
    buf[0] = 0x67; buf[1] = 0x56;
    /* Chunk data length */
    uint16_t hdr_len = (uint16_t)(total - 4);
    buf[2] = (uint8_t)((hdr_len >> 8) & 0xFF);
    buf[3] = (uint8_t)(hdr_len & 0xFF);

    /* Timestamp (64-bit, microseconds) */
    uint64_t ts_be = htobe64(send_ts_us);
    memcpy(buf + 4, &ts_be, 8);

    /* Version */
    buf[12] = 2;  /* version high */
    buf[13] = 0;  /* version low */
    /* Frame ID */
    buf[14] = (uint8_t)(seq_num & 0xFF);
    /* Frame packet count */
    buf[15] = 1;

    /* Tracker list sub-chunk at offset 16 */
    /* Chunk ID: 0x0000 (tracker list) */
    buf[16] = 0x00; buf[17] = 0x00;
    uint16_t tracker_len = (uint16_t)(total - 20);
    buf[18] = (uint8_t)((tracker_len >> 8) & 0xFF);
    buf[19] = (uint8_t)(tracker_len & 0xFF);

    /* Tracker 0 sub-chunk at offset 20 */
    /* Chunk ID: tracker ID */
    buf[20] = 0x00; buf[21] = 0x00;
    uint16_t tdata_len = (uint16_t)(total - 24);
    buf[22] = (uint8_t)((tdata_len >> 8) & 0xFF);
    buf[23] = (uint8_t)(tdata_len & 0xFF);

    /* Tracker position: x, y, z as int32 fixed-point (multiply by 1000) */
    int32_t x = (int32_t)(seq_num % 1000) * 1000;
    int32_t y = (int32_t)((seq_num * 7) % 1000) * 1000;
    int32_t z = 0;
    uint32_t x_be = htonl((uint32_t)x);
    uint32_t y_be = htonl((uint32_t)y);
    uint32_t z_be = htonl((uint32_t)z);
    memcpy(buf + 24, &x_be, 4);
    memcpy(buf + 28, &y_be, 4);
    memcpy(buf + 32, &z_be, 4);

    /* Fill remaining with test pattern */
    for (int i = 36; i < total; i++)
        buf[i] = (uint8_t)((seq_num + (uint32_t)i) & 0xFF);

    /* WLTP trailer */
    wltp_trailer_t tr;
    tr.magic      = htonl(WLTP_MAGIC);
    tr.seq_num    = htonl(seq_num);
    tr.send_ts_us = htobe64(send_ts_us);
    tr.proto_id   = htons(PROTO_PSN);
    tr.flags      = 0;
    memcpy(buf + total, &tr, sizeof(tr));

    return total + (int)sizeof(wltp_trailer_t);
}
