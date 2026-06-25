#include "proto.h"
#include <string.h>
#include <arpa/inet.h>
#include <endian.h>

extern int build_artnet(uint8_t *buf, int sz, uint32_t seq, usec_t ts, uint16_t uni, int pkt_size);
extern int build_sacn(uint8_t *buf, int sz, uint32_t seq, usec_t ts, uint16_t uni, int pkt_size);
extern int build_osc(uint8_t *buf, int sz, uint32_t seq, usec_t ts, uint16_t uni, int pkt_size);
extern int build_manet2(uint8_t *buf, int sz, uint32_t seq, usec_t ts, uint16_t uni, int pkt_size);
extern int build_rtpmidi(uint8_t *buf, int sz, uint32_t seq, usec_t ts, uint16_t uni, int pkt_size);
extern int build_psn(uint8_t *buf, int sz, uint32_t seq, usec_t ts, uint16_t uni, int pkt_size);
extern int build_klingnet(uint8_t *buf, int sz, uint32_t seq, usec_t ts, uint16_t uni, int pkt_size);
extern int build_citp(uint8_t *buf, int sz, uint32_t seq, usec_t ts, uint16_t uni, int pkt_size);
extern int build_kinet(uint8_t *buf, int sz, uint32_t seq, usec_t ts, uint16_t uni, int pkt_size);

static proto_def_t registry[PROTO_COUNT];

void proto_init(void) {
    registry[PROTO_ARTNET] = (proto_def_t){
        .id = PROTO_ARTNET, .name = "Art-Net", .short_name = "artnet",
        .transport = TRANSPORT_UDP, .port = 6454,
        .use_multicast = 0, .mcast_addr = 0,
        .min_pkt_size = 530, .max_pkt_size = 638, .typical_pkt_size = 530,
        .build = build_artnet
    };
    registry[PROTO_SACN] = (proto_def_t){
        .id = PROTO_SACN, .name = "sACN", .short_name = "sacn",
        .transport = TRANSPORT_UDP, .port = 5568,
        .use_multicast = 1, .mcast_addr = 0,
        .min_pkt_size = 638, .max_pkt_size = 638, .typical_pkt_size = 638,
        .build = build_sacn
    };
    registry[PROTO_OSC] = (proto_def_t){
        .id = PROTO_OSC, .name = "OSC", .short_name = "osc",
        .transport = TRANSPORT_UDP, .port = 8000,
        .use_multicast = 0, .mcast_addr = 0,
        .min_pkt_size = 36, .max_pkt_size = 1472, .typical_pkt_size = 64,
        .build = build_osc
    };
    registry[PROTO_MANET2] = (proto_def_t){
        .id = PROTO_MANET2, .name = "MA-Net2", .short_name = "manet2",
        .transport = TRANSPORT_UDP, .port = 6474,
        .use_multicast = 1, .mcast_addr = 0,
        .min_pkt_size = 500, .max_pkt_size = 1472, .typical_pkt_size = 1000,
        .build = build_manet2
    };
    registry[PROTO_RTPMIDI] = (proto_def_t){
        .id = PROTO_RTPMIDI, .name = "RTP-MIDI", .short_name = "rtpmidi",
        .transport = TRANSPORT_UDP, .port = 5004,
        .use_multicast = 0, .mcast_addr = 0,
        .min_pkt_size = 16, .max_pkt_size = 120, .typical_pkt_size = 32,
        .build = build_rtpmidi
    };
    registry[PROTO_PSN] = (proto_def_t){
        .id = PROTO_PSN, .name = "PSN", .short_name = "psn",
        .transport = TRANSPORT_UDP, .port = 56565,
        .use_multicast = 1, .mcast_addr = 0,
        .min_pkt_size = 100, .max_pkt_size = 1000, .typical_pkt_size = 200,
        .build = build_psn
    };
    registry[PROTO_KLINGNET] = (proto_def_t){
        .id = PROTO_KLINGNET, .name = "Kling-Net", .short_name = "klingnet",
        .transport = TRANSPORT_UDP, .port = 4948,
        .use_multicast = 0, .mcast_addr = 0,
        .min_pkt_size = 64, .max_pkt_size = 1472, .typical_pkt_size = 512,
        .build = build_klingnet
    };
    registry[PROTO_CITP] = (proto_def_t){
        .id = PROTO_CITP, .name = "CITP", .short_name = "citp",
        .transport = TRANSPORT_UDP, .port = 4809,
        .use_multicast = 1, .mcast_addr = 0,
        .min_pkt_size = 100, .max_pkt_size = 1472, .typical_pkt_size = 512,
        .build = build_citp
    };
    registry[PROTO_KINET] = (proto_def_t){
        .id = PROTO_KINET, .name = "KiNET", .short_name = "kinet",
        .transport = TRANSPORT_UDP, .port = 6038,
        .use_multicast = 0, .mcast_addr = 0,
        .min_pkt_size = 533, .max_pkt_size = 533, .typical_pkt_size = 533,
        .build = build_kinet
    };

    /* Resolve multicast addresses now that inet_addr is available */
    registry[PROTO_SACN].mcast_addr = inet_addr("239.255.0.1");
    registry[PROTO_MANET2].mcast_addr = inet_addr("239.192.0.1");
    registry[PROTO_PSN].mcast_addr = inet_addr("236.10.10.10");
    registry[PROTO_CITP].mcast_addr = inet_addr("224.0.0.180");
}

const proto_def_t *proto_get(proto_id_t id) {
    if ((int)id < 0 || id >= PROTO_COUNT) return NULL;
    return &registry[id];
}

const proto_def_t *proto_find(const char *short_name) {
    for (int i = 0; i < PROTO_COUNT; i++) {
        if (strcmp(registry[i].short_name, short_name) == 0)
            return &registry[i];
    }
    return NULL;
}

int proto_parse_list(const char *list) {
    if (!list || list[0] == '\0')
        return 0;

    if (strcmp(list, "all") == 0)
        return (1 << PROTO_COUNT) - 1;

    int mask = 0;
    char buf[256];
    strncpy(buf, list, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    char *saveptr = NULL;
    char *tok = strtok_r(buf, ",", &saveptr);
    while (tok) {
        const proto_def_t *p = proto_find(tok);
        if (!p)
            return 0;
        mask |= (1 << p->id);
        tok = strtok_r(NULL, ",", &saveptr);
    }
    return mask;
}

int proto_effective_pkt_size(const proto_def_t *proto, int requested_size) {
    int size;

    if (!proto)
        return 0;

    size = (requested_size > 0) ? requested_size : proto->typical_pkt_size;
    if (size < proto->min_pkt_size)
        size = proto->min_pkt_size;
    if (size > proto->max_pkt_size)
        size = proto->max_pkt_size;

    return size;
}

int proto_extract_trailer(const uint8_t *buf, int len, wltp_trailer_t *out) {
    if (len < (int)sizeof(wltp_trailer_t))
        return 0;
    wltp_trailer_t tmp;
    memcpy(&tmp, buf + len - (int)sizeof(wltp_trailer_t), sizeof(tmp));
    if (ntohl(tmp.magic) != WLTP_MAGIC)
        return 0;
    *out = tmp;
    return 1;
}

void proto_update_sacn_universe(uint16_t universe) {
    registry[PROTO_SACN].mcast_addr = htonl(0xEFFF0000u | (uint32_t)universe);
}
