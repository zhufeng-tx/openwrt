/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef REMOTE_TESTER_COMMAND_H
#define REMOTE_TESTER_COMMAND_H

#include <stddef.h>
#include <stdint.h>

struct blob_attr;
struct rt_command_agent;

#define RT_COMMAND_UUID_BYTES 16U
#define RT_COMMAND_DATA_MAX 160U
#define RT_COMMAND_WRITE_CHUNK 32U
#define RT_COMMAND_MAX_CHUNKS 16U

enum rt_command_kind {
    RT_COMMAND_STATUS = 1,
    RT_COMMAND_UART_WRITE = 2,
    RT_COMMAND_IPERF_START = 3,
    RT_COMMAND_IPERF_STOP = 4,
};

struct rt_command {
    uint8_t request_uuid[RT_COMMAND_UUID_BYTES];
    uint8_t kind;
    uint8_t chunk_index;
    uint8_t chunk_count;
    uint8_t data_length;
    uint8_t data[RT_COMMAND_DATA_MAX];
};

struct rt_command_result {
    uint8_t request_uuid[RT_COMMAND_UUID_BYTES];
    uint8_t kind;
    uint8_t chunk_index;
    uint8_t status;          /* 0 accepted/written, errno value otherwise */
    uint16_t written;        /* UART bytes confirmed by the node */
};

int rt_command_uuid_parse(const char *text, uint8_t out[RT_COMMAND_UUID_BYTES]);
void rt_command_uuid_format(const uint8_t uuid[RT_COMMAND_UUID_BYTES], char out[37]);
int rt_command_encode(const struct rt_command *command, uint8_t *output,
    size_t capacity, size_t *length);
int rt_command_decode(const uint8_t *input, size_t length,
    struct rt_command *command);
int rt_command_result_encode(const struct rt_command_result *result,
    uint8_t *output, size_t capacity, size_t *length);
int rt_command_result_decode(const uint8_t *input, size_t length,
    struct rt_command_result *result);

/* Converts one desktop host request into one or up to 16 RF commands. */
int rt_command_prepare_host(const char *type, const char *request_id,
    struct blob_attr *payload, struct rt_command commands[RT_COMMAND_MAX_CHUNKS],
    size_t *command_count);

typedef void (*rt_command_iperf_event_cb)(void *context,
    const uint8_t request_uuid[RT_COMMAND_UUID_BYTES], int exit_status);
struct rt_command_agent *rt_command_agent_start(int serial_fd,
    rt_command_iperf_event_cb event, void *context);
void rt_command_agent_stop(struct rt_command_agent *agent);
int rt_command_agent_iperf_active(const struct rt_command_agent *agent);
/* Execute one authenticated, replay-checked RF command and cache its outcome. */
int rt_command_agent_execute(struct rt_command_agent *agent,
    const struct rt_command *command, struct rt_command_result *result);

#endif
