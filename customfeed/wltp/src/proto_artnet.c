#include "types.h"
#include <string.h>
#include <arpa/inet.h>
#include <endian.h>

int build_artnet(uint8_t *buf, int buf_size, uint32_t seq_num,
                 usec_t send_ts_us, uint16_t universe, int pkt_size)
{
    const int hdr_len = 18;
    const int total = (pkt_size > 0) ? pkt_size : hdr_len + 512;
    const int dmx_len = total - hdr_len;
    if (total < hdr_len) return -1;
    if (buf_size < total + (int)sizeof(wltp_trailer_t)) return -1;

    memset(buf, 0, (size_t)total);

    /* Art-Net ID */
    memcpy(buf, "Art-Net\0", 8);
    /* OpCode: ArtDmx = 0x5000 (little-endian) */
    buf[8] = 0x00; buf[9] = 0x50;
    /* Protocol version 14 (big-endian) */
    buf[10] = 0x00; buf[11] = 14;
    /* Sequence */
    buf[12] = (uint8_t)(seq_num & 0xFF);
    /* Physical port */
    buf[13] = 0;
    /* Universe (little-endian, 15-bit) */
    buf[14] = (uint8_t)(universe & 0xFF);
    buf[15] = (uint8_t)((universe >> 8) & 0x7F);
    /* DMX data length (big-endian) */
    buf[16] = (uint8_t)((dmx_len >> 8) & 0xFF);
    buf[17] = (uint8_t)(dmx_len & 0xFF);

    /* Fill DMX data with test pattern */
    for (int i = 0; i < dmx_len; i++)
        buf[hdr_len + i] = (uint8_t)((seq_num + (uint32_t)i) & 0xFF);

    /* WLTP trailer at end */
    wltp_trailer_t t;
    t.magic      = htonl(WLTP_MAGIC);
    t.seq_num    = htonl(seq_num);
    t.send_ts_us = htobe64(send_ts_us);
    t.proto_id   = htons(PROTO_ARTNET);
    t.flags      = 0;
    memcpy(buf + total, &t, sizeof(t));

    return total + (int)sizeof(wltp_trailer_t);
}
