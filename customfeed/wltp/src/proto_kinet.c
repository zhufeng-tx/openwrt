#include "types.h"
#include <string.h>
#include <arpa/inet.h>
#include <endian.h>

int build_kinet(uint8_t *buf, int buf_size, uint32_t seq_num,
                usec_t send_ts_us, uint16_t universe, int pkt_size)
{
    (void)pkt_size;
    const int hdr_len = 21;
    const int dmx_len = 512;
    const int total = hdr_len + dmx_len;
    if (buf_size < total + (int)sizeof(wltp_trailer_t)) return -1;

    memset(buf, 0, (size_t)total);

    /* KiNET Magic: 0x0401DC4A */
    buf[0] = 0x04; buf[1] = 0x01; buf[2] = 0xDC; buf[3] = 0x4A;
    /* Version: 0x0100 */
    buf[4] = 0x01; buf[5] = 0x00;
    /* Type: DMXOUT = 0x0101 */
    buf[6] = 0x01; buf[7] = 0x01;
    /* Sequence number (big-endian) */
    uint32_t seq_be = htonl(seq_num);
    memcpy(buf + 8, &seq_be, 4);
    /* Port */
    buf[12] = 0;
    /* Padding */
    buf[13] = 0;
    /* Flags */
    buf[14] = 0x00; buf[15] = 0x00;
    /* Timer (big-endian) */
    uint32_t timer = htonl((uint32_t)(send_ts_us / 1000));
    memcpy(buf + 16, &timer, 4);
    /* Universe */
    buf[20] = (uint8_t)(universe & 0xFF);

    /* DMX data */
    for (int i = 0; i < dmx_len; i++)
        buf[hdr_len + i] = (uint8_t)((seq_num + (uint32_t)i) & 0xFF);

    /* WLTP trailer */
    wltp_trailer_t t;
    t.magic      = htonl(WLTP_MAGIC);
    t.seq_num    = htonl(seq_num);
    t.send_ts_us = htobe64(send_ts_us);
    t.proto_id   = htons(PROTO_KINET);
    t.flags      = 0;
    memcpy(buf + total, &t, sizeof(t));

    return total + (int)sizeof(wltp_trailer_t);
}
