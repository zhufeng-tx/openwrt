#include "types.h"
#include <string.h>
#include <arpa/inet.h>
#include <endian.h>

int build_rtpmidi(uint8_t *buf, int buf_size, uint32_t seq_num,
                  usec_t send_ts_us, uint16_t universe, int pkt_size)
{
    (void)universe;
    const int rtp_hdr = 12;
    const int midi_cmd = 4;  /* flags + 3 MIDI bytes */
    const int min_total = rtp_hdr + midi_cmd;
    const int total = (pkt_size > 0) ? pkt_size : min_total;
    if (total < min_total) return -1;
    if (buf_size < total + (int)sizeof(wltp_trailer_t)) return -1;

    memset(buf, 0, (size_t)total);

    /* RTP Header */
    buf[0] = 0x80;  /* V=2, P=0, X=0, CC=0 */
    buf[1] = 0x61;  /* M=0, PT=97 (RTP-MIDI) */

    /* Sequence number (big-endian) */
    uint16_t seq16 = (uint16_t)(seq_num & 0xFFFF);
    buf[2] = (uint8_t)((seq16 >> 8) & 0xFF);
    buf[3] = (uint8_t)(seq16 & 0xFF);

    /* Timestamp (big-endian, 32-bit from lower 32 bits of usec) */
    uint32_t ts32 = htonl((uint32_t)(send_ts_us & 0xFFFFFFFF));
    memcpy(buf + 4, &ts32, 4);

    /* SSRC */
    uint32_t ssrc = htonl(0x574C5450);  /* "WLTP" */
    memcpy(buf + 8, &ssrc, 4);

    /* MIDI command section: no flags, 3 bytes */
    buf[12] = 0x03;  /* length of MIDI list */
    buf[13] = 0x90;  /* Note On, channel 0 */
    buf[14] = 0x3C;  /* note 60 (middle C) */
    buf[15] = 0x7F;  /* velocity 127 */

    for (int i = min_total; i < total; i++)
        buf[i] = (uint8_t)((seq_num + (uint32_t)i) & 0xFF);

    /* WLTP trailer */
    wltp_trailer_t t;
    t.magic      = htonl(WLTP_MAGIC);
    t.seq_num    = htonl(seq_num);
    t.send_ts_us = htobe64(send_ts_us);
    t.proto_id   = htons(PROTO_RTPMIDI);
    t.flags      = 0;
    memcpy(buf + total, &t, sizeof(t));

    return total + (int)sizeof(wltp_trailer_t);
}
