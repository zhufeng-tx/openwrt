# MT7628 remote tester network

`remote-tester-radio` is the sole owner of the board's SX1262. Its default
`diagnostic` role retains bounded probe, scan, receive, and one-shot TX
operations. Set `role` to `controller` on one MT7628 or `node` on at most eight
other MT7628 units. There is no manager election or mesh forwarding. The
experimental ESP32-P4/Waveshare protocol v2 is a separate wire protocol.

## Provisioning

The service reads `/etc/config/remote-tester-radio` at startup. Network TX
requires all three explicit options: `network_tx_enabled '1'`,
`antenna_confirmed '1'`, and `lab_mode '1'`. All default to `0`. Keep them at
`0` until the fitted module, antenna, and permitted lab RF setup are known.
Setting a role without these options allows local configuration and receive
work but does not authorize scheduled or contention transmissions.

Keys are 32 bytes represented by exactly 64 lowercase hex digits and an
optional final newline. Create regular root-owned files with mode `0600`.
Install the same beacon key on controller and nodes, a distinct node PSK on
each node, and a separate host PSK on the controller. The controller's
`nodes.keys` registry has one active row per node:

```text
<16-lowercase-hex-EUI> <64-lowercase-hex-node-PSK>
```

The controller assigns stable radio IDs 1–8 in registry row order after an
authenticated EUI join. Reject duplicate EUIs. A node's `node_eui` must match
one registry row and its `node_psk_file` must contain that row's key. Key and
registry files should be provisioned through a trusted local path; neither
the radio join nor the desktop host API creates keys.

For a controller, set `host_port` (default `45671`), `host_uart` (UART1/HAT
UART path), `node_port` (default `45670` for optional bridge offload), and the
host/beacon/registry key paths. The host service and its host PSK are used only
in the controller role. For a node, set `serial_device` to its DUT UART or USB
serial TTY, `node_eui`, the node/beacon key paths, and
`controller_ipv4` to the address reachable through the DUT bridge. The board's
console UART0 is separate from the HAT UART1; verify device paths on the
assembled board before use. Nodes do not need a host PSK or host UART service.
`host_uart` and `serial_device` both default to `/dev/ttyS1`, so configure one
role per radio and do not run the controller host service and node serial
reader against the same UART on one board.

## Transport behavior

The controller broadcasts a beacon every 2-second network frame. It grants
up to 16 ordered TDMA opportunities and reserves a controller downlink
interval plus a final 250 ms CAD contention interval. A short demand lease
keeps recently active nodes scheduled and expires after silence. Synchronized nodes send
directly in their grants; join, slot requests, and recovery use randomized
backoff and CAD. Missing the expected beacon invalidates the current grants.
Each packet grant reserves the full DATA airtime rounded up to milliseconds,
plus a 2 ms timer-dispatch and PHY-start margin. Separate grants retain their
20 ms interslot guard; confirm both timings against MT7628 scheduling and DIO1
jitter on the assembled board.
Beacon ACK bitmaps selectively acknowledge fragments of independently
compressed log blocks. Low-rate serial data is flushed into an independent
block after 3 seconds; bursts can fill blocks up to 4 KiB sooner.

Nodes retain unacknowledged blocks in a bounded RAM queue. Authenticated TCP
over the DUT bridge is preferred for logs when available; the same block ID
and byte offset support replay over LoRa after IP failure. A node reboot
starts a new stream epoch and marks its unknown volatile tail as lost; queue
overflow reports known dropped ranges. Host connection and node bridge
offload use different controller TCP ports. The desktop may use host TCP or
UART1 and supplies the controller's host PSK for a mutual challenge. Each
subsequent host frame carries a session-bound HMAC and sequence counter;
UART CRC detects accidental framing damage. RF logs are authenticated, not
encrypted.

`STATUS`, bounded DUT UART writes, and iPerf start/stop are typed commands;
there is no shell-command packet. iPerf control may travel over authenticated
LoRa, while iPerf test traffic uses IP. During a test, bulk bridge log offload
pauses and the node uses capped LoRa grants, buffering the remainder.

## Validation boundary

Native framing/core tests, a deterministic shared-medium simulation, and an
OpenWrt MIPS package build establish software and cross-build behavior only.
The simulated 70 B/s formatted-log workload delivered every byte from three
and eight nodes with p95 capture-to-delivery latency below 10 seconds. This
result depends on its radio profile, packet model, and formatted-log compression;
it is not a guarantee for incompressible logs or real RF. The PCB is unfinished.
Before enabling network TX on real hardware, confirm the RF region/profile and antenna, then measure
MT7628-to-MT7628 TX/RX/CAD, DIO1 timing, multi-node grants, UART capture,
bridge failover, queue overflow, command results, and eight-node log latency.
No simulator, fake PHY, or cross-build result is RF proof.
