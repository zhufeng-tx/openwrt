#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <endian.h>
#include <poll.h>
#include <errno.h>
#include <ctype.h>
#include <limits.h>

#include "types.h"
#include "config.h"
#include "proto.h"
#include "net.h"
#include "stats.h"
#include "clock.h"

static volatile sig_atomic_t g_stop = 0;

static void signal_handler(int sig) {
    (void)sig;
    g_stop = 1;
}

static const char *mode_name(run_mode_t mode) {
    switch (mode) {
    case MODE_SENDER: return "sender";
    case MODE_RECEIVER: return "receiver";
    case MODE_REFLECTOR: return "reflector";
    default: return "unknown";
    }
}

static int parse_int_arg(const char *name, const char *arg, int min, int max, int *out) {
    char *end = NULL;
    long val;

    if (!arg || arg[0] == '\0') {
        fprintf(stderr, "Invalid %s: empty value\n", name);
        return 0;
    }

    errno = 0;
    val = strtol(arg, &end, 10);
    if (errno != 0 || end == arg || *end != '\0' || val < min || val > max) {
        fprintf(stderr, "Invalid %s: %s (expected %d..%d)\n", name, arg, min, max);
        return 0;
    }

    *out = (int)val;
    return 1;
}

static int iface_valid(const char *iface) {
    size_t len;

    if (!iface || iface[0] == '\0')
        return 0;

    len = strlen(iface);
    if (len >= 32)
        return 0;

    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)iface[i];
        if (!(isalnum(c) || c == '_' || c == '-' || c == '.' || c == ':' || c == '@'))
            return 0;
    }
    return 1;
}

static void json_print_string(const char *s) {
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

static int proto_count_enabled(int proto_mask) {
    int count = 0;
    for (int i = 0; i < PROTO_COUNT; i++)
        if (proto_mask & (1 << i))
            count++;
    return count;
}

static void print_status_json(const test_config_t *cfg) {
    printf("{\"record\":\"status\",\"version\":");
    json_print_string(WLTP_VERSION_STR);
    printf(",\"mode\":");
    json_print_string(mode_name(cfg->mode));
    printf(",\"iface\":");
    json_print_string(cfg->iface);
    printf(",\"rate_pps\":%d,\"duration_sec\":%d,\"interval_sec\":%d,"
           "\"universe\":%u,\"pkt_size\":%d,\"burst_count\":%d,"
           "\"protocol_count\":%d}\n",
           cfg->pkt_rate, cfg->duration_sec, cfg->report_interval,
           (unsigned int)cfg->universe, cfg->pkt_size, cfg->burst_count,
           proto_count_enabled(cfg->proto_mask));
    fflush(stdout);
}

static void print_usage(const char *prog) {
    fprintf(stderr,
        "WLTP v%s - Wireless Lighting Throughput Profiler\n\n"
        "Usage: %s -m <mode> -i <iface> [options]\n\n"
        "Modes:\n"
        "  -m sender       Generate protocol traffic\n"
        "  -m receiver     Measure incoming traffic\n"
        "  -m reflector    Receive and echo back (for RTT)\n\n"
        "Required:\n"
        "  -i <iface>      Network interface (e.g., wlan0)\n\n"
        "Options:\n"
        "  -p <protos>     Comma-separated protocols or 'all' (default: all)\n"
        "                  Names: artnet,sacn,osc,manet2,rtpmidi,psn,klingnet,citp,kinet\n"
        "  -r <rate>       Aggregate packets/sec across all enabled protocols (default: %d)\n"
        "                  Each protocol receives rate/num_protocols pps\n"
        "  -d <seconds>    Test duration, 0=infinite (default: %d)\n"
        "  -t <seconds>    Report interval (default: %d)\n"
        "  -u <universe>   DMX universe number (default: 1)\n"
        "  -D <ip>         Destination IP (required for sender)\n"
        "  -s <bytes>      Protocol payload size, clamped per protocol (default: protocol-specific)\n"
        "  -b <count>      Burst count (default: 1)\n"
        "  -J              Emit JSON-lines status, interval, and final records\n"
        "  -v              Verbose output\n"
        "  -h              Show this help\n",
        WLTP_VERSION_STR, prog,
        WLTP_DEFAULT_RATE, WLTP_DEFAULT_DURATION, WLTP_DEFAULT_INTERVAL);
}

/* Shared context for threads */
typedef struct {
    test_config_t  *cfg;
    proto_stats_t  *stats;
    int            *sockets;
    volatile sig_atomic_t *stop_flag;
} shared_ctx_t;

static void *sender_thread(void *arg) {
    shared_ctx_t *ctx = (shared_ctx_t *)arg;
    test_config_t *cfg = ctx->cfg;

    /* Build list of enabled protocols */
    int num_protos = 0;
    proto_id_t proto_ids[PROTO_COUNT];
    for (int i = 0; i < PROTO_COUNT; i++) {
        if (cfg->proto_mask & (1 << i)) {
            proto_ids[num_protos] = (proto_id_t)i;
            num_protos++;
        }
    }
    if (num_protos == 0) return NULL;

    /* -r is aggregate pps; -b sends a group, then sleeps for the group's share. */
    int burst_count = (cfg->burst_count > 0) ? cfg->burst_count : 1;
    usec_t interval_us = (1000000ULL * (uint64_t)burst_count) /
                         (uint64_t)(cfg->pkt_rate > 0 ? cfg->pkt_rate : 1);
    if (interval_us == 0)
        interval_us = 1;
    uint32_t seq[PROTO_COUNT] = {0};
    int proto_idx = 0;
    uint8_t pkt_buf[WLTP_MAX_PKT_SIZE + sizeof(wltp_trailer_t) + 256];

    while (!*ctx->stop_flag) {
        usec_t t_start = clock_now_us();

        for (int b = 0; b < burst_count && !*ctx->stop_flag; b++) {
            usec_t send_ts = clock_now_us();
            int pi = proto_ids[proto_idx];
            const proto_def_t *p = proto_get(pi);
            int pkt_size = proto_effective_pkt_size(p, cfg->pkt_size);

            int pkt_len = p->build(pkt_buf, (int)sizeof(pkt_buf), seq[pi], send_ts,
                                   cfg->universe, pkt_size);
            if (pkt_len > 0) {
                int sent = net_send_udp(ctx->sockets[pi], pkt_buf, pkt_len, p, cfg);
                if (sent > 0)
                    stats_record_tx(pi, sent);
            }

            seq[pi]++;
            proto_idx = (proto_idx + 1) % num_protos;
        }

        /* Rate limiting */
        usec_t elapsed = clock_elapsed_us(t_start, clock_now_us());
        if (elapsed < interval_us)
            clock_sleep_us(interval_us - elapsed);
    }

    return NULL;
}

static void *receiver_thread(void *arg) {
    shared_ctx_t *ctx = (shared_ctx_t *)arg;
    test_config_t *cfg = ctx->cfg;

    /* Set up poll array for all enabled protocol sockets */
    struct pollfd fds[PROTO_COUNT];
    int nfds = 0;

    for (int i = 0; i < PROTO_COUNT; i++) {
        if ((cfg->proto_mask & (1 << i)) && ctx->sockets[i] >= 0) {
            fds[nfds].fd = ctx->sockets[i];
            fds[nfds].events = POLLIN;
            fds[nfds].revents = 0;
            nfds++;
        }
    }
    if (nfds == 0) return NULL;

    uint8_t pkt_buf[WLTP_MAX_PKT_SIZE + sizeof(wltp_trailer_t) + 256];

    while (!*ctx->stop_flag) {
        int ret = poll(fds, (nfds_t)nfds, WLTP_POLL_TIMEOUT_MS);
        if (ret <= 0) continue;

        for (int i = 0; i < nfds; i++) {
            if (!(fds[i].revents & POLLIN)) continue;

            ssize_t len = recv(fds[i].fd, pkt_buf, sizeof(pkt_buf), 0);
            if (len <= 0) continue;

            usec_t recv_ts = clock_now_us();
            wltp_trailer_t trailer;
            if (!proto_extract_trailer(pkt_buf, (int)len, &trailer)) continue;

            uint32_t seq_num = ntohl(trailer.seq_num);
            usec_t send_ts = be64toh(trailer.send_ts_us);
            proto_id_t pid = (proto_id_t)ntohs(trailer.proto_id);
            if (pid >= PROTO_COUNT) continue;

            stats_record_rx(pid, (int)len, seq_num, send_ts, recv_ts);

            /* Reflector mode: echo packet back */
            if (cfg->mode == MODE_REFLECTOR) {
                /* flags is the last 2 bytes of wltp_trailer_t */
                uint16_t reply_flags = htons(0x0002);
                memcpy(pkt_buf + (size_t)len - 2, &reply_flags, sizeof(reply_flags));

                const proto_def_t *p = proto_get(pid);
                if (p) {
                    struct sockaddr_in dest;
                    memset(&dest, 0, sizeof(dest));
                    dest.sin_family = AF_INET;
                    dest.sin_port = htons(p->port);
                    dest.sin_addr.s_addr = cfg->dest_ip ? cfg->dest_ip : INADDR_BROADCAST;
                    sendto(fds[i].fd, pkt_buf, (size_t)len, 0,
                           (struct sockaddr *)&dest, sizeof(dest));
                }
            }
        }
    }

    return NULL;
}

int main(int argc, char *argv[]) {
    test_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.mode = MODE_RECEIVER;
    cfg.proto_mask = (1 << PROTO_COUNT) - 1;
    cfg.pkt_rate = WLTP_DEFAULT_RATE;
    cfg.duration_sec = WLTP_DEFAULT_DURATION;
    cfg.report_interval = WLTP_DEFAULT_INTERVAL;
    cfg.universe = 1;
    cfg.burst_count = 1;

    proto_init();

    int opt;
    while ((opt = getopt(argc, argv, "m:i:p:r:d:t:u:D:s:b:Jvh")) != -1) {
        switch (opt) {
        case 'm':
            if (strcmp(optarg, "sender") == 0) cfg.mode = MODE_SENDER;
            else if (strcmp(optarg, "receiver") == 0) cfg.mode = MODE_RECEIVER;
            else if (strcmp(optarg, "reflector") == 0) cfg.mode = MODE_REFLECTOR;
            else { fprintf(stderr, "Unknown mode: %s\n", optarg); return 1; }
            break;
        case 'i':
            if (!iface_valid(optarg)) {
                fprintf(stderr, "Invalid interface: %s\n", optarg ? optarg : "");
                return 1;
            }
            strncpy(cfg.iface, optarg, sizeof(cfg.iface) - 1);
            cfg.iface[sizeof(cfg.iface) - 1] = '\0';
            break;
        case 'p':
            cfg.proto_mask = proto_parse_list(optarg);
            if (cfg.proto_mask == 0) {
                fprintf(stderr, "No valid protocols specified\n");
                return 1;
            }
            break;
        case 'r':
            if (!parse_int_arg("rate", optarg, 1, 1000000, &cfg.pkt_rate)) return 1;
            break;
        case 'd':
            if (!parse_int_arg("duration", optarg, 0, INT_MAX, &cfg.duration_sec)) return 1;
            break;
        case 't':
            if (!parse_int_arg("interval", optarg, 1, 86400, &cfg.report_interval)) return 1;
            break;
        case 'u': {
            int universe;
            if (!parse_int_arg("universe", optarg, 0, 65535, &universe)) return 1;
            cfg.universe = (uint16_t)universe;
            break;
        }
        case 'D': {
            struct in_addr a;
            if (inet_pton(AF_INET, optarg, &a) != 1) {
                fprintf(stderr, "Invalid destination IP: %s\n", optarg);
                return 1;
            }
            cfg.dest_ip = a.s_addr;
            break;
        }
        case 's':
            if (!parse_int_arg("packet size", optarg, 1, WLTP_MAX_PKT_SIZE, &cfg.pkt_size)) return 1;
            break;
        case 'b':
            if (!parse_int_arg("burst count", optarg, 1, 10000, &cfg.burst_count)) return 1;
            break;
        case 'J': cfg.json_output = 1; break;
        case 'v': cfg.verbose = 1; break;
        case 'h': print_usage(argv[0]); return 0;
        default:  print_usage(argv[0]); return 1;
        }
    }

    if (optind < argc) {
        fprintf(stderr, "Unexpected argument: %s\n", argv[optind]);
        return 1;
    }

    proto_update_sacn_universe(cfg.universe);

    if (cfg.iface[0] == '\0') {
        fprintf(stderr, "Error: -i <interface> is required\n");
        return 1;
    }
    if (cfg.mode == MODE_SENDER && cfg.dest_ip == 0) {
        fprintf(stderr, "Error: sender mode requires -D <dest_ip>\n");
        return 1;
    }

    stats_init();

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    if (!cfg.json_output) {
        /* Print configuration header */
        printf("WLTP v%s - Wireless Lighting Throughput Profiler\n", WLTP_VERSION_STR);
        printf("Mode: %s | Interface: %s | Rate: %d pps | Duration: %ds | Burst: %d\n",
               cfg.mode == MODE_SENDER ? "SENDER" :
               cfg.mode == MODE_RECEIVER ? "RECEIVER" : "REFLECTOR",
               cfg.iface, cfg.pkt_rate, cfg.duration_sec, cfg.burst_count);
        printf("Protocols:");
        for (int i = 0; i < PROTO_COUNT; i++)
            if (cfg.proto_mask & (1 << i)) {
                const proto_def_t *p = proto_get((proto_id_t)i);
                printf(" %s[%d]", p->name,
                       proto_effective_pkt_size(p, cfg.pkt_size));
            }
        printf("\n---\n");
        fflush(stdout);
    }

    /* Create sockets for each enabled protocol */
    int sockets[PROTO_COUNT];
    for (int i = 0; i < PROTO_COUNT; i++) sockets[i] = -1;
    int is_sender = (cfg.mode == MODE_SENDER);
    int active_mask = cfg.proto_mask;

    for (int i = 0; i < PROTO_COUNT; i++) {
        if (!(active_mask & (1 << i))) continue;
        const proto_def_t *p = proto_get((proto_id_t)i);
        sockets[i] = net_create_udp(p, &cfg, is_sender);
        if (sockets[i] < 0) {
            fprintf(stderr, "Failed to create socket for %s: ", p->name);
            perror("");
            active_mask &= ~(1 << i);
        }
    }
    cfg.proto_mask = active_mask;

    if (cfg.proto_mask == 0) {
        fprintf(stderr, "Error: no usable protocol sockets\n");
        return 1;
    }

    if (cfg.json_output)
        print_status_json(&cfg);

    shared_ctx_t sctx;
    sctx.cfg = &cfg;
    sctx.stats = g_stats;
    sctx.sockets = sockets;
    sctx.stop_flag = &g_stop;

    pthread_t sender_tid, receiver_tid;
    int sender_started = 0, receiver_started = 0;

    if (cfg.mode == MODE_SENDER) {
        if (pthread_create(&sender_tid, NULL, sender_thread, &sctx) == 0)
            sender_started = 1;
    }
    if (cfg.mode == MODE_RECEIVER || cfg.mode == MODE_REFLECTOR) {
        if (pthread_create(&receiver_tid, NULL, receiver_thread, &sctx) == 0)
            receiver_started = 1;
    }

    /* Main thread: reporting loop */
    usec_t test_start = clock_now_us();
    usec_t last_report = test_start;

    while (!g_stop) {
        clock_sleep_us(100000);  /* 100ms granularity */

        usec_t now = clock_now_us();

        if (cfg.duration_sec > 0) {
            usec_t elapsed = clock_elapsed_us(test_start, now);
            if (elapsed >= (usec_t)cfg.duration_sec * 1000000ULL) {
                g_stop = 1;
                break;
            }
        }

        usec_t since_report = clock_elapsed_us(last_report, now);
        if (since_report >= (usec_t)cfg.report_interval * 1000000ULL) {
            if (cfg.json_output)
                stats_print_interval_json(cfg.proto_mask, since_report);
            else
                stats_print_interval(cfg.proto_mask, since_report);
            last_report = now;
        }
    }

    /* Wait for threads */
    if (sender_started) pthread_join(sender_tid, NULL);
    if (receiver_started) pthread_join(receiver_tid, NULL);

    /* Final summary */
    usec_t total_elapsed = clock_elapsed_us(test_start, clock_now_us());
    if (cfg.json_output)
        stats_print_summary_json(cfg.proto_mask, total_elapsed);
    else
        stats_print_summary(cfg.proto_mask, total_elapsed);

    /* Clean up */
    for (int i = 0; i < PROTO_COUNT; i++) {
        if (sockets[i] < 0) continue;
        if (!is_sender) {
            const proto_def_t *p = proto_get((proto_id_t)i);
            if (p && p->use_multicast && p->mcast_addr) {
                struct ip_mreq mreq;
                memset(&mreq, 0, sizeof(mreq));
                mreq.imr_multiaddr.s_addr = p->mcast_addr;
                mreq.imr_interface.s_addr = INADDR_ANY;
                setsockopt(sockets[i], IPPROTO_IP, IP_DROP_MEMBERSHIP,
                           &mreq, sizeof(mreq));
            }
        }
        close(sockets[i]);
    }

    return 0;
}
