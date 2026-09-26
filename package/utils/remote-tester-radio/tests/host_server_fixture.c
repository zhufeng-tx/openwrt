/* SPDX-License-Identifier: GPL-2.0-only */
#include "../src/host/rt_host_server.h"
#include <errno.h>
#include <libubox/blobmsg.h>
#include <libubox/uloop.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static int request_cb(void *context, const char *type, const char *request_id,
    uint8_t node_id, struct blob_attr *payload, struct blob_buf *result)
{
    (void)context; (void)request_id; (void)node_id; (void)payload;
    if (strcmp(type, "node.discover")) return -EINVAL;
    void *nodes = blobmsg_open_array(result, "nodes");
    void *node = blobmsg_open_table(result, NULL);
    blobmsg_add_u32(result, "nodeId", 1);
    blobmsg_add_string(result, "mac", "0011223344556677");
    blobmsg_add_string(result, "hostname", "mt7628-node-1");
    blobmsg_add_string(result, "ipv4", "");
    blobmsg_add_u32(result, "lastSeen", 1);
    blobmsg_add_string(result, "state", "online");
    void *capabilities = blobmsg_open_array(result, "capabilities");
    blobmsg_add_string(result, NULL, "serial");
    blobmsg_add_string(result, NULL, "iperf3");
    blobmsg_close_array(result, capabilities);
    blobmsg_close_table(result, node);
    blobmsg_close_array(result, nodes);
    return 0;
}

static void stop_cb(int signal_number)
{
    (void)signal_number;
    uloop_end();
}

int main(int argc, char **argv)
{
    struct rt_host_server *server;
    char *end;
    unsigned long port;
    if (argc != 2) return 2;
    port = strtoul(argv[1], &end, 10);
    if (!argv[1][0] || *end || port == 0 || port > UINT16_MAX) return 2;
    if (uloop_init()) return 1;
    server = rt_host_server_start((uint16_t)port, "", "test", request_cb, NULL);
    if (!server) { uloop_done(); return 1; }
    signal(SIGTERM, stop_cb);
    signal(SIGINT, stop_cb);
    uloop_run();
    rt_host_server_stop(server);
    uloop_done();
    return 0;
}
