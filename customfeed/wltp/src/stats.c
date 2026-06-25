#include "stats.h"
#include "proto.h"

#include <stdio.h>
#include <string.h>
#include <pthread.h>

proto_stats_t g_stats[PROTO_COUNT];
pthread_mutex_t g_stats_lock = PTHREAD_MUTEX_INITIALIZER;

static void stats_print_json_string(const char *s) {
    putchar('"');
    while (s && *s) {
        unsigned char c = (unsigned char)*s++;
        switch (c) {
        case '"': printf("\\\""); break;
        case '\\': printf("\\\\"); break;
        case '\b': printf("\\b"); break;
        case '\f': printf("\\f"); break;
        case '\n': printf("\\n"); break;
        case '\r': printf("\\r"); break;
        case '\t': printf("\\t"); break;
        default:
            if (c < 0x20)
                printf("\\u%04x", c);
            else
                putchar(c);
            break;
        }
    }
    putchar('"');
}

static void stats_print_json_metrics(const char *record, const proto_def_t *p,
                                     const proto_stats_t *s, usec_t elapsed_us,
                                     int interval)
{
    uint64_t tx_packets = interval ? s->interval_tx_packets : s->tx_packets;
    uint64_t tx_bytes = interval ? s->interval_tx_bytes : s->tx_bytes;
    uint64_t rx_packets = interval ? s->interval_rx_packets : s->rx_packets;
    uint64_t rx_bytes = interval ? s->interval_rx_bytes : s->rx_bytes;
    uint64_t lost = interval ? s->interval_rx_lost : s->rx_lost;
    uint64_t lat_sum = interval ? s->interval_lat_sum_us : s->lat_sum_us;
    uint64_t lat_count = interval ? s->interval_lat_count : s->lat_count;
    uint64_t lat_min = interval ? s->interval_lat_min_us : s->lat_min_us;
    uint64_t lat_max = interval ? s->interval_lat_max_us : s->lat_max_us;
    uint64_t bytes = (rx_packets > 0) ? rx_bytes : tx_bytes;
    uint64_t pkts = (rx_packets > 0) ? rx_packets : tx_packets;
    uint64_t bps = 0, pps = 0, lat_avg = 0, loss_pct_x100 = 0;
    uint64_t total_expected = rx_packets + lost;

    if (elapsed_us > 0) {
        bps = (bytes * 1000000ULL) / elapsed_us;
        pps = (pkts * 1000000ULL) / elapsed_us;
    }
    if (lat_count > 0)
        lat_avg = lat_sum / lat_count;
    if (total_expected > 0)
        loss_pct_x100 = (lost * 10000ULL) / total_expected;

    printf("{\"record\":");
    stats_print_json_string(record);
    printf(",\"protocol_id\":%d,\"protocol\":", p->id);
    stats_print_json_string(p->name);
    printf(",\"short_name\":");
    stats_print_json_string(p->short_name);
    printf(",\"tx_packets\":%llu,\"tx_bytes\":%llu,"
           "\"rx_packets\":%llu,\"rx_bytes\":%llu,"
           "\"lost_packets\":%llu,\"loss_percent\":%llu.%02llu,"
           "\"pps\":%llu,\"Bps\":%llu,"
           "\"latency_avg_us\":%llu,\"latency_min_us\":%llu,"
           "\"latency_max_us\":%llu,\"jitter_us\":%llu}\n",
           (unsigned long long)tx_packets,
           (unsigned long long)tx_bytes,
           (unsigned long long)rx_packets,
           (unsigned long long)rx_bytes,
           (unsigned long long)lost,
           (unsigned long long)(loss_pct_x100 / 100),
           (unsigned long long)(loss_pct_x100 % 100),
           (unsigned long long)pps,
           (unsigned long long)bps,
           (unsigned long long)lat_avg,
           (unsigned long long)(lat_min == UINT64_MAX ? 0 : lat_min),
           (unsigned long long)lat_max,
           (unsigned long long)s->jitter_us);
}

void stats_init(void) {
    memset(g_stats, 0, sizeof(g_stats));
    for (int i = 0; i < PROTO_COUNT; i++) {
        g_stats[i].lat_min_us = UINT64_MAX;
        g_stats[i].interval_lat_min_us = UINT64_MAX;
    }
}

void stats_record_tx(proto_id_t id, int bytes) {
    pthread_mutex_lock(&g_stats_lock);
    proto_stats_t *s = &g_stats[id];
    s->tx_packets++;
    s->tx_bytes += (uint64_t)bytes;
    s->interval_tx_packets++;
    s->interval_tx_bytes += (uint64_t)bytes;
    pthread_mutex_unlock(&g_stats_lock);
}

void stats_record_rx(proto_id_t id, int bytes, uint32_t seq_num,
                     usec_t send_ts_us, usec_t recv_ts_us)
{
    pthread_mutex_lock(&g_stats_lock);
    proto_stats_t *s = &g_stats[id];

    s->rx_packets++;
    s->rx_bytes += (uint64_t)bytes;
    s->interval_rx_packets++;
    s->interval_rx_bytes += (uint64_t)bytes;

    if (s->rx_seq_initialized) {
        uint32_t expected = s->rx_last_seq + 1;
        if (seq_num > expected) {
            uint32_t gap = seq_num - expected;
            s->rx_lost += gap;
            s->rx_seq_errors++;
            s->interval_rx_lost += gap;
        }
    }
    s->rx_last_seq = seq_num;
    s->rx_seq_initialized = 1;

    int64_t transit = (int64_t)recv_ts_us - (int64_t)send_ts_us;
    uint64_t lat = (transit >= 0) ? (uint64_t)transit : (uint64_t)(-transit);

    if (lat < s->lat_min_us) s->lat_min_us = lat;
    if (lat > s->lat_max_us) s->lat_max_us = lat;
    if (lat < s->interval_lat_min_us) s->interval_lat_min_us = lat;
    if (lat > s->interval_lat_max_us) s->interval_lat_max_us = lat;
    s->lat_sum_us += lat;
    s->lat_count++;
    s->interval_lat_sum_us += lat;
    s->interval_lat_count++;

    if (s->jitter_initialized) {
        int64_t d = transit - s->last_transit_us;
        if (d < 0) d = -d;
        s->jitter_us += ((uint64_t)d - s->jitter_us + 8) >> 4;
    }
    s->last_transit_us = transit;
    s->jitter_initialized = 1;

    pthread_mutex_unlock(&g_stats_lock);
}

void stats_print_interval(int proto_mask, usec_t interval_us) {
    pthread_mutex_lock(&g_stats_lock);
    for (int i = 0; i < PROTO_COUNT; i++) {
        if (!(proto_mask & (1 << i))) continue;
        proto_stats_t *s = &g_stats[i];
        const proto_def_t *p = proto_get((proto_id_t)i);

        if (s->interval_rx_packets == 0 && s->interval_tx_packets == 0)
            continue;

        uint64_t bps = 0, pps = 0;
        uint64_t bytes = (s->interval_rx_packets > 0) ?
                          s->interval_rx_bytes : s->interval_tx_bytes;
        uint64_t pkts = (s->interval_rx_packets > 0) ?
                         s->interval_rx_packets : s->interval_tx_packets;

        if (interval_us > 0) {
            bps = (bytes * 1000000ULL) / interval_us;
            pps = (pkts * 1000000ULL) / interval_us;
        }

        uint64_t lat_avg = 0;
        if (s->interval_lat_count > 0)
            lat_avg = s->interval_lat_sum_us / s->interval_lat_count;

        uint64_t loss_pct_x100 = 0;
        uint64_t total_expected = s->interval_rx_packets + s->interval_rx_lost;
        if (total_expected > 0)
            loss_pct_x100 = (s->interval_rx_lost * 10000ULL) / total_expected;

        printf("%-10s | %7llu pps | %10llu B/s | "
               "lat min/avg/max/jit %llu/%llu/%llu/%llu us | "
               "loss %llu.%02llu%%\n",
               p->name,
               (unsigned long long)pps,
               (unsigned long long)bps,
               (unsigned long long)(s->interval_lat_min_us == UINT64_MAX ? 0 : s->interval_lat_min_us),
               (unsigned long long)lat_avg,
               (unsigned long long)s->interval_lat_max_us,
               (unsigned long long)s->jitter_us,
               (unsigned long long)(loss_pct_x100 / 100),
               (unsigned long long)(loss_pct_x100 % 100));

        s->interval_tx_packets = 0;
        s->interval_tx_bytes = 0;
        s->interval_rx_packets = 0;
        s->interval_rx_bytes = 0;
        s->interval_lat_sum_us = 0;
        s->interval_lat_count = 0;
        s->interval_rx_lost = 0;
        s->interval_lat_min_us = UINT64_MAX;
        s->interval_lat_max_us = 0;
    }
    pthread_mutex_unlock(&g_stats_lock);
    printf("---\n");
    fflush(stdout);
}

void stats_print_interval_json(int proto_mask, usec_t interval_us) {
    pthread_mutex_lock(&g_stats_lock);
    for (int i = 0; i < PROTO_COUNT; i++) {
        if (!(proto_mask & (1 << i))) continue;
        proto_stats_t *s = &g_stats[i];
        const proto_def_t *p = proto_get((proto_id_t)i);

        if (s->interval_rx_packets == 0 && s->interval_tx_packets == 0)
            continue;

        stats_print_json_metrics("interval", p, s, interval_us, 1);

        s->interval_tx_packets = 0;
        s->interval_tx_bytes = 0;
        s->interval_rx_packets = 0;
        s->interval_rx_bytes = 0;
        s->interval_lat_sum_us = 0;
        s->interval_lat_count = 0;
        s->interval_rx_lost = 0;
        s->interval_lat_min_us = UINT64_MAX;
        s->interval_lat_max_us = 0;
    }
    pthread_mutex_unlock(&g_stats_lock);
    fflush(stdout);
}

void stats_print_summary(int proto_mask, usec_t total_us) {
    pthread_mutex_lock(&g_stats_lock);
    printf("\n=== FINAL SUMMARY (%llu.%02llus) ===\n",
           (unsigned long long)(total_us / 1000000ULL),
           (unsigned long long)((total_us / 10000ULL) % 100));
    printf("%-10s | %9s | %9s | %7s | %6s | %9s | %11s | %9s\n",
           "Protocol", "TX pkts", "RX pkts", "Lost", "Loss%",
           "Avg B/s", "Avg lat us", "Jitter us");

    for (int i = 0; i < PROTO_COUNT; i++) {
        if (!(proto_mask & (1 << i))) continue;
        proto_stats_t *s = &g_stats[i];
        const proto_def_t *p = proto_get((proto_id_t)i);

        uint64_t avg_bps = 0;
        if (total_us > 0 && s->rx_bytes > 0)
            avg_bps = (s->rx_bytes * 1000000ULL) / total_us;
        else if (total_us > 0 && s->tx_bytes > 0)
            avg_bps = (s->tx_bytes * 1000000ULL) / total_us;

        uint64_t avg_lat = 0;
        if (s->lat_count > 0)
            avg_lat = s->lat_sum_us / s->lat_count;

        uint64_t loss_pct_x100 = 0;
        uint64_t total_expected = s->rx_packets + s->rx_lost;
        if (total_expected > 0)
            loss_pct_x100 = (s->rx_lost * 10000ULL) / total_expected;

        printf("%-10s | %9llu | %9llu | %7llu | %3llu.%02llu | %9llu | %11llu | %9llu\n",
               p->name,
               (unsigned long long)s->tx_packets,
               (unsigned long long)s->rx_packets,
               (unsigned long long)s->rx_lost,
               (unsigned long long)(loss_pct_x100 / 100),
               (unsigned long long)(loss_pct_x100 % 100),
               (unsigned long long)avg_bps,
               (unsigned long long)avg_lat,
               (unsigned long long)s->jitter_us);
    }
    printf("===\n");
    fflush(stdout);
    pthread_mutex_unlock(&g_stats_lock);
}

void stats_print_summary_json(int proto_mask, usec_t total_us) {
    pthread_mutex_lock(&g_stats_lock);
    for (int i = 0; i < PROTO_COUNT; i++) {
        if (!(proto_mask & (1 << i))) continue;
        proto_stats_t *s = &g_stats[i];
        const proto_def_t *p = proto_get((proto_id_t)i);

        stats_print_json_metrics("final", p, s, total_us, 0);
    }
    fflush(stdout);
    pthread_mutex_unlock(&g_stats_lock);
}

void stats_reset_interval(void) {
    pthread_mutex_lock(&g_stats_lock);
    for (int i = 0; i < PROTO_COUNT; i++) {
        g_stats[i].interval_tx_packets = 0;
        g_stats[i].interval_tx_bytes = 0;
        g_stats[i].interval_rx_packets = 0;
        g_stats[i].interval_rx_bytes = 0;
        g_stats[i].interval_lat_sum_us = 0;
        g_stats[i].interval_lat_count = 0;
        g_stats[i].interval_rx_lost = 0;
        g_stats[i].interval_lat_min_us = UINT64_MAX;
        g_stats[i].interval_lat_max_us = 0;
    }
    pthread_mutex_unlock(&g_stats_lock);
}
