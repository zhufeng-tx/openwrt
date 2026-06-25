#ifndef WLTP_NET_H
#define WLTP_NET_H

#include "types.h"

int net_create_udp(const proto_def_t *proto, const test_config_t *cfg,
                   int is_sender);

int net_send_udp(int sockfd, const uint8_t *buf, int len,
                 const proto_def_t *proto, const test_config_t *cfg);

int net_recv_udp(int sockfd, uint8_t *buf, int buf_size, int timeout_ms);

#endif
