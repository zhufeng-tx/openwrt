/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef REMOTE_TESTER_NETWORK_RUNTIME_H
#define REMOTE_TESTER_NETWORK_RUNTIME_H

#include "radio_core.h"
#include "rt_command.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct blob_buf;
struct radio_linux;
struct rt_network_runtime;

/* Optional deterministic transport seam for host tests; production uses radio_linux. */
struct rt_network_phy_ops {
	int (*start_receive)(void *context, uint8_t payload_len, bool continuous);
	int (*start_transmit)(void *context, const uint8_t *data, size_t length);
	int (*start_cad)(void *context);
	int (*cad_result)(void *context, bool *busy);
	int (*get_rx)(void *context, uint8_t *data, size_t capacity, size_t *length);
};

struct rt_network_clock_ops {
	uint64_t (*now_us)(void *context);
};

struct rt_network_test_peer {
	uint8_t eui[8];
	uint8_t psk[32];
};

enum rt_network_role {
	RT_NETWORK_DISABLED = 0,
	RT_NETWORK_CONTROLLER,
	RT_NETWORK_NODE,
};

/* Strings and the radio are borrowed for the lifetime of the runtime. */
struct rt_network_config {
	enum rt_network_role role;
	uint32_t network_id;
	const char *node_eui;             /* 16 lowercase hexadecimal characters */
	const char *beacon_key_path;
	const char *node_psk_path;
	const char *node_registry_path;   /* EUI and PSK rows; row order assigns IDs */
	const char *host_psk_path;
	const char *controller_ipv4;      /* node TCP offload endpoint */
	const char *host_uart_path;       /* desktop host-control UART */
	const char *serial_path;          /* target log/command UART */
	uint16_t host_port;
	uint16_t node_port;
	size_t queue_bytes;
	uint32_t airtime_budget_us;
	struct radio_linux *radio;
	struct radio_config radio_profile;
	bool transmit_enabled;            /* caller has applied both TX safety gates */
	const struct rt_network_phy_ops *phy_ops;
	const struct rt_network_clock_ops *clock_ops;
	void *io_context;
	void *clock_context;
	/* Key/registry injection is accepted only with the optional fake PHY seam. */
	const uint8_t *test_beacon_key;
	const uint8_t *test_node_key;
	const struct rt_network_test_peer *test_registry;
	size_t test_registry_count;
	uint64_t test_boot_nonce;          /* nonzero deterministic epoch for fake-PHY tests */
};

int rt_network_runtime_start(struct rt_network_runtime **runtime,
	const struct rt_network_config *config);
int rt_network_runtime_on_irq(struct rt_network_runtime *runtime, uint16_t irq,
	uint64_t irq_monotonic_us);
/* Drives due timers deterministically when a fake clock is supplied. */
int rt_network_runtime_tick(struct rt_network_runtime *runtime);
int rt_network_runtime_capture(struct rt_network_runtime *runtime,
	const uint8_t *bytes, size_t length);
/* Fake-PHY-only deterministic branch hook for retry-exhaustion recovery tests. */
int rt_network_runtime_test_exhaust_fragment(struct rt_network_runtime *runtime,
	uint8_t fragment_index, bool with_later_overflow_gap);
/* Fake-PHY-only GAP ACK/state hooks used by deterministic recovery tests. */
int rt_network_runtime_test_mark_gap_sent(struct rt_network_runtime *runtime);
int rt_network_runtime_test_ack_gap(struct rt_network_runtime *runtime);
int rt_network_runtime_test_delivery_offset(const struct rt_network_runtime *runtime,
	uint8_t node_id, uint32_t stream_id, uint32_t *next_offset);
uint32_t rt_network_runtime_test_airtime_us(const struct radio_config *profile,
	size_t packet_length);
int rt_network_runtime_test_set_peer_demand(struct rt_network_runtime *runtime,
	uint8_t node_id, uint64_t node_boot_nonce, uint32_t requested_airtime_us);
int rt_network_runtime_test_set_frame_number(struct rt_network_runtime *runtime,
	uint32_t frame_number);
/* Fake-PHY-only hooks for authenticated command epoch and iPerf lifecycle tests. */
int rt_network_runtime_test_record_iperf_start(struct rt_network_runtime *runtime,
	const struct rt_command *command, const struct rt_command_result *result);
int rt_network_runtime_test_iperf_complete(struct rt_network_runtime *runtime,
	const uint8_t request_uuid[RT_COMMAND_UUID_BYTES], int exit_status);
int rt_network_runtime_test_iperf_state(const struct rt_network_runtime *runtime,
	uint8_t active_uuid[RT_COMMAND_UUID_BYTES],
	uint8_t event_uuid[RT_COMMAND_UUID_BYTES], bool *event_pending);
void rt_network_runtime_stop(struct rt_network_runtime *runtime);
void rt_network_runtime_add_status(const struct rt_network_runtime *runtime,
	struct blob_buf *buffer);

#endif
