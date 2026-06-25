#ifndef WLTP_STATS_H
#define WLTP_STATS_H

#include "types.h"

extern proto_stats_t g_stats[PROTO_COUNT];
extern pthread_mutex_t g_stats_lock;

void stats_init(void);
void stats_record_tx(proto_id_t id, int bytes);
void stats_record_rx(proto_id_t id, int bytes, uint32_t seq_num,
                     usec_t send_ts_us, usec_t recv_ts_us);
void stats_print_interval(int proto_mask, usec_t interval_us);
void stats_print_interval_json(int proto_mask, usec_t interval_us);
void stats_print_summary(int proto_mask, usec_t total_us);
void stats_print_summary_json(int proto_mask, usec_t total_us);
void stats_reset_interval(void);

#endif
