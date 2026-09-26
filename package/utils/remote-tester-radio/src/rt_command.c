/* SPDX-License-Identifier: GPL-2.0-only */
#define _GNU_SOURCE
#include "rt_command.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <libubox/blobmsg.h>
#include <libubox/uloop.h>
#include <libubox/utils.h>
#include <mbedtls/base64.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define COMMAND_CACHE_SIZE 32U
#define COMMAND_WRITE_MAX (RT_COMMAND_WRITE_CHUNK * RT_COMMAND_MAX_CHUNKS)
#define IPERF_START_BYTES 29U

#ifndef RT_COMMAND_IPERF_PATH
#define RT_COMMAND_IPERF_PATH "/usr/bin/iperf3"
#endif

struct command_cache_entry {
    bool used;
    struct rt_command command;
    struct rt_command_result result;
};

struct rt_command_agent {
    int serial_fd;
    struct command_cache_entry cache[COMMAND_CACHE_SIZE];
    uint8_t next_cache;
    struct uloop_process iperf_process;
    struct uloop_timeout stop_timeout;
    bool iperf_active;
    uint8_t iperf_test_uuid[RT_COMMAND_UUID_BYTES];
    rt_command_iperf_event_cb event;
    void *context;
};

static int hex_digit(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

int rt_command_uuid_parse(const char *text, uint8_t out[RT_COMMAND_UUID_BYTES])
{
    size_t output = 0;
    if (!text || !out || strlen(text) != 36) return -EINVAL;
    for (size_t i = 0; i < 36;) {
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            if (text[i++] != '-') return -EINVAL;
            continue;
        }
        int high = hex_digit(text[i++]);
        int low = hex_digit(text[i++]);
        if (high < 0 || low < 0 || output >= RT_COMMAND_UUID_BYTES)
            return -EINVAL;
        out[output++] = (uint8_t)((high << 4) | low);
    }
    return output == RT_COMMAND_UUID_BYTES ? 0 : -EINVAL;
}

void rt_command_uuid_format(const uint8_t uuid[RT_COMMAND_UUID_BYTES], char out[37])
{
    static const char digits[] = "0123456789abcdef";
    size_t offset = 0;
    for (size_t i = 0; i < RT_COMMAND_UUID_BYTES; i++) {
        if (i == 4 || i == 6 || i == 8 || i == 10) out[offset++] = '-';
        out[offset++] = digits[uuid[i] >> 4];
        out[offset++] = digits[uuid[i] & 15];
    }
    out[offset] = '\0';
}

static bool valid_command(const struct rt_command *command)
{
    if (!command || command->kind < RT_COMMAND_STATUS ||
        command->kind > RT_COMMAND_IPERF_STOP ||
        command->chunk_count == 0 || command->chunk_count > RT_COMMAND_MAX_CHUNKS ||
        command->chunk_index >= command->chunk_count ||
        command->data_length > RT_COMMAND_DATA_MAX) return false;
    if (command->kind != RT_COMMAND_UART_WRITE &&
        (command->chunk_index || command->chunk_count != 1)) return false;
    if (command->kind == RT_COMMAND_UART_WRITE &&
        (command->data_length == 0 || command->data_length > RT_COMMAND_WRITE_CHUNK))
        return false;
    if (command->kind == RT_COMMAND_STATUS && command->data_length) return false;
    if (command->kind == RT_COMMAND_IPERF_START &&
        command->data_length != IPERF_START_BYTES) return false;
    if (command->kind == RT_COMMAND_IPERF_STOP &&
        command->data_length != RT_COMMAND_UUID_BYTES) return false;
    return true;
}

int rt_command_encode(const struct rt_command *command, uint8_t *output,
    size_t capacity, size_t *length)
{
    if (!valid_command(command) || !output || !length) return -EINVAL;
    if (capacity < 20U + command->data_length) return -ENOSPC;
    memcpy(output, command->request_uuid, RT_COMMAND_UUID_BYTES);
    output[16] = command->kind;
    output[17] = command->chunk_index;
    output[18] = command->chunk_count;
    output[19] = command->data_length;
    memcpy(output + 20, command->data, command->data_length);
    *length = 20U + command->data_length;
    return 0;
}

int rt_command_decode(const uint8_t *input, size_t length,
    struct rt_command *command)
{
    if (!input || !command || length < 20 || length > 20U + RT_COMMAND_DATA_MAX ||
        length != 20U + input[19]) return -EINVAL;
    memset(command, 0, sizeof(*command));
    memcpy(command->request_uuid, input, RT_COMMAND_UUID_BYTES);
    command->kind = input[16];
    command->chunk_index = input[17];
    command->chunk_count = input[18];
    command->data_length = input[19];
    memcpy(command->data, input + 20, command->data_length);
    return valid_command(command) ? 0 : -EINVAL;
}

int rt_command_result_encode(const struct rt_command_result *result,
    uint8_t *output, size_t capacity, size_t *length)
{
    if (!result || !output || !length || capacity < 21 ||
        result->kind < RT_COMMAND_STATUS || result->kind > RT_COMMAND_IPERF_STOP ||
        result->chunk_index >= RT_COMMAND_MAX_CHUNKS) return -EINVAL;
    memcpy(output, result->request_uuid, 16);
    output[16] = result->kind;
    output[17] = result->chunk_index;
    output[18] = result->status;
    output[19] = (uint8_t)(result->written >> 8);
    output[20] = (uint8_t)result->written;
    *length = 21;
    return 0;
}

int rt_command_result_decode(const uint8_t *input, size_t length,
    struct rt_command_result *result)
{
    if (!input || !result || length != 21 ||
        input[16] < RT_COMMAND_STATUS || input[16] > RT_COMMAND_IPERF_STOP ||
        input[17] >= RT_COMMAND_MAX_CHUNKS) return -EINVAL;
    memcpy(result->request_uuid, input, 16);
    result->kind = input[16];
    result->chunk_index = input[17];
    result->status = input[18];
    result->written = ((uint16_t)input[19] << 8) | input[20];
    return 0;
}

enum write_field { WRITE_DATA, __WRITE_FIELD_MAX };
static const struct blobmsg_policy write_policy[] = {
    [WRITE_DATA] = { .name = "data", .type = BLOBMSG_TYPE_STRING },
};
enum iperf_field {
    IPERF_TEST_ID, IPERF_TARGET, IPERF_PORT, IPERF_DURATION,
    IPERF_PROTOCOL, IPERF_BANDWIDTH, __IPERF_FIELD_MAX
};
static const struct blobmsg_policy iperf_policy[] = {
    [IPERF_TEST_ID] = { .name = "testId", .type = BLOBMSG_TYPE_STRING },
    [IPERF_TARGET] = { .name = "targetHost", .type = BLOBMSG_TYPE_STRING },
    [IPERF_PORT] = { .name = "port", .type = BLOBMSG_TYPE_INT32 },
    [IPERF_DURATION] = { .name = "durationSeconds", .type = BLOBMSG_TYPE_INT32 },
    [IPERF_PROTOCOL] = { .name = "protocol", .type = BLOBMSG_TYPE_STRING },
    [IPERF_BANDWIDTH] = { .name = "bandwidth", .type = BLOBMSG_TYPE_INT32 },
};

int rt_command_prepare_host(const char *type, const char *request_id,
    struct blob_attr *payload, struct rt_command commands[RT_COMMAND_MAX_CHUNKS],
    size_t *command_count)
{
    uint8_t request_uuid[16];
    if (!type || !request_id || !commands || !command_count ||
        rt_command_uuid_parse(request_id, request_uuid)) return -EINVAL;
    memset(commands, 0, sizeof(*commands) * RT_COMMAND_MAX_CHUNKS);
    *command_count = 0;
    if (!strcmp(type, "node.status")) {
        commands[0].kind = RT_COMMAND_STATUS;
        commands[0].chunk_count = 1;
        memcpy(commands[0].request_uuid, request_uuid, 16);
        *command_count = 1;
        return 0;
    }
    if (!payload) return -EINVAL;
    if (!strcmp(type, "serial.write")) {
        struct blob_attr *fields[__WRITE_FIELD_MAX];
        uint8_t decoded[COMMAND_WRITE_MAX];
        size_t length = 0;
        blobmsg_parse(write_policy, __WRITE_FIELD_MAX, fields,
            blobmsg_data(payload), blobmsg_len(payload));
        if (!fields[WRITE_DATA] || mbedtls_base64_decode(decoded, sizeof(decoded),
            &length, (const unsigned char *)blobmsg_get_string(fields[WRITE_DATA]),
            strlen(blobmsg_get_string(fields[WRITE_DATA]))) || !length)
            return -EINVAL;
        *command_count = (length + RT_COMMAND_WRITE_CHUNK - 1) / RT_COMMAND_WRITE_CHUNK;
        for (size_t i = 0; i < *command_count; i++) {
            struct rt_command *command = &commands[i];
            size_t start = i * RT_COMMAND_WRITE_CHUNK;
            size_t chunk = length - start < RT_COMMAND_WRITE_CHUNK ?
                length - start : RT_COMMAND_WRITE_CHUNK;
            memcpy(command->request_uuid, request_uuid, 16);
            command->kind = RT_COMMAND_UART_WRITE;
            command->chunk_index = (uint8_t)i;
            command->chunk_count = (uint8_t)*command_count;
            command->data_length = (uint8_t)chunk;
            memcpy(command->data, decoded + start, chunk);
        }
        return 0;
    }
    if (!strcmp(type, "iperf.start") || !strcmp(type, "iperf.stop")) {
        struct blob_attr *fields[__IPERF_FIELD_MAX];
        struct rt_command *command = &commands[0];
        uint8_t test_uuid[16];
        blobmsg_parse(iperf_policy, __IPERF_FIELD_MAX, fields,
            blobmsg_data(payload), blobmsg_len(payload));
        if (!fields[IPERF_TEST_ID] ||
            rt_command_uuid_parse(blobmsg_get_string(fields[IPERF_TEST_ID]), test_uuid))
            return -EINVAL;
        memcpy(command->request_uuid, request_uuid, 16);
        command->chunk_count = 1;
        memcpy(command->data, test_uuid, 16);
        if (!strcmp(type, "iperf.stop")) {
            command->kind = RT_COMMAND_IPERF_STOP;
            command->data_length = 16;
        } else {
            struct in_addr address;
            uint32_t port, duration, bandwidth = 0;
            const char *protocol;
            if (!fields[IPERF_TARGET] || !fields[IPERF_PORT] ||
                !fields[IPERF_DURATION] || !fields[IPERF_PROTOCOL] ||
                inet_pton(AF_INET, blobmsg_get_string(fields[IPERF_TARGET]),
                    &address) != 1) return -EINVAL;
            port = blobmsg_get_u32(fields[IPERF_PORT]);
            duration = blobmsg_get_u32(fields[IPERF_DURATION]);
            if (!port || port > 65535 || !duration || duration > 3600)
                return -EINVAL;
            protocol = blobmsg_get_string(fields[IPERF_PROTOCOL]);
            if (strcmp(protocol, "tcp") && strcmp(protocol, "udp")) return -EINVAL;
            if (fields[IPERF_BANDWIDTH]) bandwidth = blobmsg_get_u32(fields[IPERF_BANDWIDTH]);
            if (bandwidth > 100000000U) return -EINVAL;
            if (!strcmp(protocol, "udp") && bandwidth == 0) bandwidth = 1000000U;
            memcpy(command->data + 16, &address, 4);
            command->data[20] = (uint8_t)(port >> 8);
            command->data[21] = (uint8_t)port;
            command->data[22] = (uint8_t)(duration >> 8);
            command->data[23] = (uint8_t)duration;
            command->data[24] = !strcmp(protocol, "udp") ? 1 : 0;
            command->data[25] = (uint8_t)(bandwidth >> 24);
            command->data[26] = (uint8_t)(bandwidth >> 16);
            command->data[27] = (uint8_t)(bandwidth >> 8);
            command->data[28] = (uint8_t)bandwidth;
            command->kind = RT_COMMAND_IPERF_START;
            command->data_length = IPERF_START_BYTES;
        }
        *command_count = 1;
        return 0;
    }
    return -ENOTSUP;
}

static void iperf_process_cb(struct uloop_process *process, int wait_status)
{
    struct rt_command_agent *agent = container_of(process,
        struct rt_command_agent, iperf_process);
    int exit_status = WIFEXITED(wait_status) ? WEXITSTATUS(wait_status) :
        WIFSIGNALED(wait_status) ? 128 + WTERMSIG(wait_status) : EIO;
    agent->iperf_active = false;
    agent->iperf_process.pid = 0;
    uloop_timeout_cancel(&agent->stop_timeout);
    if (agent->event)
        agent->event(agent->context, agent->iperf_test_uuid, exit_status);
}

static void iperf_stop_timeout_cb(struct uloop_timeout *timer)
{
    struct rt_command_agent *agent = container_of(timer,
        struct rt_command_agent, stop_timeout);
    if (agent->iperf_active && agent->iperf_process.pid > 0)
        (void)kill(agent->iperf_process.pid, SIGKILL);
}

struct rt_command_agent *rt_command_agent_start(int serial_fd,
    rt_command_iperf_event_cb event, void *context)
{
    struct rt_command_agent *agent = calloc(1, sizeof(*agent));
    if (!agent) return NULL;
    agent->serial_fd = serial_fd;
    agent->event = event;
    agent->context = context;
    agent->iperf_process.cb = iperf_process_cb;
    agent->stop_timeout.cb = iperf_stop_timeout_cb;
    return agent;
}

void rt_command_agent_stop(struct rt_command_agent *agent)
{
    if (!agent) return;
    uloop_timeout_cancel(&agent->stop_timeout);
    if (agent->iperf_active && agent->iperf_process.pid > 0) {
        pid_t pid = agent->iperf_process.pid;
        uloop_process_delete(&agent->iperf_process);
        (void)kill(pid, SIGKILL);
        (void)waitpid(pid, NULL, WNOHANG);
    }
    memset(agent, 0, sizeof(*agent));
    free(agent);
}

int rt_command_agent_iperf_active(const struct rt_command_agent *agent)
{
    return agent && agent->iperf_active;
}

static int start_iperf(struct rt_command_agent *agent,
    const struct rt_command *command)
{
    struct in_addr address;
    char address_text[INET_ADDRSTRLEN], port_text[8], duration_text[8], bandwidth_text[16];
    uint16_t port, duration;
    uint32_t bandwidth;
    pid_t pid;
    if (agent->iperf_active) return EBUSY;
    if (access(RT_COMMAND_IPERF_PATH, X_OK)) return ENOENT;
    memcpy(&address, command->data + 16, 4);
    if (!inet_ntop(AF_INET, &address, address_text, sizeof(address_text))) return EINVAL;
    port = ((uint16_t)command->data[20] << 8) | command->data[21];
    duration = ((uint16_t)command->data[22] << 8) | command->data[23];
    bandwidth = ((uint32_t)command->data[25] << 24) |
        ((uint32_t)command->data[26] << 16) |
        ((uint32_t)command->data[27] << 8) | command->data[28];
    if (!port || !duration || duration > 3600 || command->data[24] > 1 ||
        bandwidth > 100000000U) return EINVAL;
    snprintf(port_text, sizeof(port_text), "%u", port);
    snprintf(duration_text, sizeof(duration_text), "%u", duration);
    snprintf(bandwidth_text, sizeof(bandwidth_text), "%u", bandwidth);
    pid = fork();
    if (pid < 0) return errno;
    if (pid == 0) {
        int null_fd = open("/dev/null", O_RDWR);
        if (null_fd >= 0) {
            (void)dup2(null_fd, STDIN_FILENO);
            (void)dup2(null_fd, STDOUT_FILENO);
            (void)dup2(null_fd, STDERR_FILENO);
            if (null_fd > STDERR_FILENO) close(null_fd);
        }
        char *argv[] = {
            RT_COMMAND_IPERF_PATH, "-c", address_text, "-p", port_text,
            "-t", duration_text, "-J", NULL, NULL, NULL, NULL
        };
        if (command->data[24]) {
            argv[8] = "-u";
            argv[9] = "-b";
            argv[10] = bandwidth_text;
        }
        execv(RT_COMMAND_IPERF_PATH, argv);
        _exit(127);
    }
    agent->iperf_process.pid = pid;
    if (uloop_process_add(&agent->iperf_process)) {
        (void)kill(pid, SIGKILL);
        (void)waitpid(pid, NULL, WNOHANG);
        agent->iperf_process.pid = 0;
        return EIO;
    }
    memcpy(agent->iperf_test_uuid, command->data, 16);
    agent->iperf_active = true;
    return 0;
}

static int stop_iperf(struct rt_command_agent *agent,
    const struct rt_command *command)
{
    if (!agent->iperf_active ||
        memcmp(agent->iperf_test_uuid, command->data, 16)) return ENOENT;
    if (kill(agent->iperf_process.pid, SIGTERM)) return errno;
    uloop_timeout_set(&agent->stop_timeout, 5000);
    return 0;
}

static struct command_cache_entry *find_cached(struct rt_command_agent *agent,
    const struct rt_command *command)
{
    for (size_t i = 0; i < COMMAND_CACHE_SIZE; i++) {
        struct command_cache_entry *entry = &agent->cache[i];
        if (entry->used && entry->command.kind == command->kind &&
            entry->command.chunk_index == command->chunk_index &&
            !memcmp(entry->command.request_uuid, command->request_uuid, 16))
            return entry;
    }
    return NULL;
}

int rt_command_agent_execute(struct rt_command_agent *agent,
    const struct rt_command *command, struct rt_command_result *result)
{
    struct command_cache_entry *cached;
    int status = 0;
    if (!agent || !valid_command(command) || !result) return -EINVAL;
    memset(result, 0, sizeof(*result));
    memcpy(result->request_uuid, command->request_uuid, 16);
    result->kind = command->kind;
    result->chunk_index = command->chunk_index;
    cached = find_cached(agent, command);
    if (cached) {
        if (cached->command.data_length == command->data_length &&
            !memcmp(cached->command.data, command->data, command->data_length))
            *result = cached->result;
        else result->status = EINVAL;
        return 0;
    }
    switch (command->kind) {
    case RT_COMMAND_STATUS:
        break;
    case RT_COMMAND_UART_WRITE: {
        ssize_t count = write(agent->serial_fd, command->data,
            command->data_length);
        if (count < 0) status = errno;
        else {
            result->written = (uint16_t)count;
            if ((size_t)count != command->data_length) status = EIO;
        }
        break;
    }
    case RT_COMMAND_IPERF_START:
        status = start_iperf(agent, command);
        break;
    case RT_COMMAND_IPERF_STOP:
        status = stop_iperf(agent, command);
        break;
    default:
        status = EINVAL;
    }
    result->status = (uint8_t)(status > UINT8_MAX ? EIO : status);
    struct command_cache_entry *entry = &agent->cache[agent->next_cache++ % COMMAND_CACHE_SIZE];
    entry->used = true;
    entry->command = *command;
    entry->result = *result;
    return 0;
}
