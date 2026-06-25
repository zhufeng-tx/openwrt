#ifndef WLTP_TYPES_H
#define WLTP_TYPES_H

#include <stdint.h>
#include <pthread.h>
#include <netinet/in.h>
#include <signal.h>

#define WLTP_MAX_PROTOCOLS   9
#define WLTP_MAX_PKT_SIZE    1472
#define WLTP_MAGIC           0x574C5450

typedef uint64_t usec_t;

typedef enum {
    TRANSPORT_UDP = 0,
    TRANSPORT_TCP = 1,
    TRANSPORT_UDP_TCP = 2
} transport_t;

typedef enum {
    PROTO_ARTNET = 0,
    PROTO_SACN,
    PROTO_OSC,
    PROTO_MANET2,
    PROTO_RTPMIDI,
    PROTO_PSN,
    PROTO_KLINGNET,
    PROTO_CITP,
    PROTO_KINET,
    PROTO_COUNT
} proto_id_t;

struct proto_def;

typedef int (*pkt_build_fn)(uint8_t *buf, int buf_size,
                            uint32_t seq_num, usec_t send_ts_us,
                            uint16_t universe, int pkt_size);

typedef struct proto_def {
    proto_id_t   id;
    const char  *name;
    const char  *short_name;
    transport_t  transport;
    uint16_t     port;
    int          use_multicast;
    uint32_t     mcast_addr;
    int          min_pkt_size;
    int          max_pkt_size;
    int          typical_pkt_size;  /* excludes WLTP trailer; wire payload = typical_pkt_size + sizeof(wltp_trailer_t) */
    pkt_build_fn build;
} proto_def_t;

typedef struct proto_stats {
    uint64_t  tx_packets;
    uint64_t  tx_bytes;
    uint64_t  rx_packets;
    uint64_t  rx_bytes;
    uint64_t  rx_seq_errors;
    uint64_t  rx_lost;

    uint64_t  lat_min_us;
    uint64_t  lat_max_us;
    uint64_t  lat_sum_us;
    uint64_t  lat_count;

    uint64_t  jitter_us;
    int64_t   last_transit_us;
    int       jitter_initialized;

    uint32_t  rx_last_seq;
    int       rx_seq_initialized;

    uint64_t  interval_tx_packets;
    uint64_t  interval_tx_bytes;
    uint64_t  interval_rx_packets;
    uint64_t  interval_rx_bytes;
    uint64_t  interval_lat_sum_us;
    uint64_t  interval_lat_count;
    uint64_t  interval_rx_lost;
    uint64_t  interval_lat_min_us;
    uint64_t  interval_lat_max_us;
} proto_stats_t;

typedef struct __attribute__((packed)) wltp_trailer {
    uint32_t  magic;
    uint32_t  seq_num;
    uint64_t  send_ts_us;
    uint16_t  proto_id;
    uint16_t  flags;
} wltp_trailer_t;

typedef enum {
    MODE_SENDER = 0,
    MODE_RECEIVER,
    MODE_REFLECTOR
} run_mode_t;

typedef struct test_config {
    run_mode_t   mode;
    char         iface[32];
    int          proto_mask;
    int          pkt_rate;
    int          duration_sec;
    int          report_interval;
    uint16_t     universe;
    uint32_t     dest_ip;
    int          pkt_size;
    int          burst_count;
    int          json_output;
    int          verbose;
} test_config_t;

typedef struct thread_ctx {
    test_config_t   *cfg;
    proto_def_t     *protos;
    proto_stats_t   *stats;
    int             *sockets;
    volatile sig_atomic_t *stop_flag;
} thread_ctx_t;

#endif
