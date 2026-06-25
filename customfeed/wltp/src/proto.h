#ifndef WLTP_PROTO_H
#define WLTP_PROTO_H

#include "types.h"

void proto_init(void);
const proto_def_t *proto_get(proto_id_t id);
const proto_def_t *proto_find(const char *short_name);
int proto_parse_list(const char *list);
int proto_effective_pkt_size(const proto_def_t *proto, int requested_size);
int proto_extract_trailer(const uint8_t *buf, int len, wltp_trailer_t *out);
void proto_update_sacn_universe(uint16_t universe);

#endif
