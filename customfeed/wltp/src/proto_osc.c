#include "types.h"
#include <string.h>
#include <arpa/inet.h>
#include <endian.h>

static int osc_pad4(int len) {
    return (len + 3) & ~3;
}

int build_osc(uint8_t *buf, int buf_size, uint32_t seq_num,
              usec_t send_ts_us, uint16_t universe, int pkt_size)
{
    (void)universe;
    int pos = 0;

    /* Address pattern: "/wltp/test" + null + padding */
    const char *addr = "/wltp/test";
    int addr_len = (int)strlen(addr) + 1;
    int addr_padded = osc_pad4(addr_len);

    /* Type tag string: ",iih" (int32, int32, int64) */
    const char *tags = ",iih";
    int tags_len = (int)strlen(tags) + 1;
    int tags_padded = osc_pad4(tags_len);

    int min_total = addr_padded + tags_padded + 4 + 4 + 8;
    int total = (pkt_size > 0) ? pkt_size : min_total;
    if (total < min_total) return -1;
    if (buf_size < total + (int)sizeof(wltp_trailer_t)) return -1;

    memset(buf, 0, (size_t)total + sizeof(wltp_trailer_t));

    memcpy(buf + pos, addr, (size_t)addr_len);
    pos = addr_padded;

    memcpy(buf + pos, tags, (size_t)tags_len);
    pos += tags_padded;

    /* Arg 1: int32 seq_num */
    uint32_t n32 = htonl(seq_num);
    memcpy(buf + pos, &n32, 4); pos += 4;

    /* Arg 2: int32 proto_id */
    n32 = htonl(PROTO_OSC);
    memcpy(buf + pos, &n32, 4); pos += 4;

    /* Arg 3: int64 timestamp */
    uint64_t n64 = htobe64(send_ts_us);
    memcpy(buf + pos, &n64, 8); pos += 8;

    for (int i = pos; i < total; i++)
        buf[i] = (uint8_t)((seq_num + (uint32_t)i) & 0xFF);

    /* WLTP trailer at end */
    wltp_trailer_t t;
    t.magic      = htonl(WLTP_MAGIC);
    t.seq_num    = htonl(seq_num);
    t.send_ts_us = htobe64(send_ts_us);
    t.proto_id   = htons(PROTO_OSC);
    t.flags      = 0;
    memcpy(buf + total, &t, sizeof(t));
    pos = total + (int)sizeof(t);

    return pos;
}
