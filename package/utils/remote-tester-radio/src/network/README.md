# Remote tester star-network core

This is an allocation-free C core for one MT7628 controller and up to eight
SX126x nodes. The radio daemon owns SPI/GPIO, monotonic time, CAD, randomness,
UCI/registry lookup, key lifetime, and transmission decisions. The native core
does not open devices or create threads.

## Wire and join contract

Frames are little-endian: a 32-byte header binds protocol version, type,
source/destination, sequence, network ID, source boot nonce, controller boot
nonce, and payload length. A 12-byte truncated HMAC-SHA256 covers the entire
header and payload. The largest encoded frame is 240 bytes, leaving 196 bytes
for payload. Each implementation call supplies the key: the controller first
uses `network_frame_peek()` to inspect an untrusted JOIN EUI, chooses the
registry PSK, then must call `network_frame_decode()` before acting on any
field. Normal node traffic uses its assigned ID and PSK. Controller beacons
can be sent once per node with that node's PSK and assigned destination, or
with a configured group key as broadcast.

An unassigned node emits a signed JOIN with source `0xff`, destination 0,
fresh nonzero 64-bit node boot nonce, controller nonce 0, and its 8-byte EUI.
The controller assigns an ID from 1 through 8 and sends a signed JOIN_RESPONSE
to `0xff` with `[assigned_id, echoed_node_nonce]`. A node is not synchronized
until the response's HMAC, network ID, and nonce echo pass replay decoding.
After choosing the ID, the controller calls `network_replay_bind_node()` with
the JOIN's boot nonce and sequence so the first assigned-ID packet continues
that replay window.
Generate independent boot nonces with the system CSPRNG on every process boot;
never use a counter that requires flash writes. The node joins again after a
missed beacon or controller boot nonce change. Replay windows are in RAM; the
controller keeps the current and two recent node nonces per EUI during its
lifetime. The node retains the current and two recent controller nonces after
it has learned them.

## Timing and queueing

The controller owns 5-second frame numbering. Beacons carry a `downlink_ms`
interval (default 200 ms); the first grant starts no earlier than
`downlink_ms + 50 ms`. The controller divides requested airtime fairly across
joined nodes and emits up to 16 chronological grants, including repeat grants
for a node. Grants have 50 ms between them and end at least 50 ms before the
final 500 ms contention window. Beacon grants are quantized to milliseconds.
At the default downlink, the scheduler clips requested airtime to 3.45 seconds
to leave room for the maximum grant guards.
Direct grant traffic must fit its assigned airtime and does not run CAD. CAD
and randomized backoff are only for JOIN and slot requests in the final
contention window. A node may use TDMA only for the exact frame whose
authenticated beacon it observed; a missing beacon immediately clears grants
and requires a fresh JOIN.

Beacons can carry one compact command entry for a node: target ID, 16-bit
sequence, command bytes, and a separate 12-byte HMAC tag under that node's PSK.
The tag binds network ID, controller nonce, beacon frame number, target,
sequence, and bytes. With all 16 grants and 8 ACKs, only 2 command bytes fit;
larger commands should use a dedicated COMMAND frame. The beacon encoder
returns `-EMSGSIZE` when the optional command does not fit.

Use `network_contention_slot_time_ms()` with the configured SF, bandwidth, and
SX126x CAD symbol count. Only that value, a caller-supplied random number, and
the retry attempt affect contention backoff. Failed frame ACKs may be retried
five times. The caller supplies its PHY airtime estimate to the scheduler.

`network_queue` is a caller-backed FIFO capped at 2 MiB. Use one shared FIFO to
enforce the total memory cap. `network_stream_builder` collects at most 4 KiB,
emits when full or after 4 seconds of inactivity, and chooses raw bytes when
Deflate does not reduce size. Every block is fragmented into at most 32 pieces
of 160 data bytes. Fragment metadata carries stream ID, block ID, raw byte
offset, codec, and block sizes. Reassembly is stop-and-wait per source: one
incomplete block per node; the caller should not start the next block until
the current block is acknowledged or abandoned. Received/missing bitmaps feed
selective ACK entries; byte offsets let the serial consumer deduplicate data
and report gaps. Reassembly slots cover controller source ID 0 and node IDs 1
through 8.

## Adaptation and attribution

Subslot timing arithmetic is independently implemented from the formula in
[LoRaMesher `SubslotScheduler` v1.0.0](https://github.com/LoRaMesher/LoRaMesher/tree/v1.0.0), pinned to commit
`31561e0c3b31f2af332ec339a728ed977cf65e37` (MIT): subtract a guard per
subslot, divide the usable window evenly, assign by identifier modulo count,
and reserve `min(30 ms, 10% of slot)` at the end. This core uses the configured
50 ms guard and does not copy LoRaMesher source.

The contention slot and random-window approach are adapted from
`meshSlotTimeMs()` and `meshTxDelayMs()` in
[jstockdale/meshtastic-lite](https://github.com/jstockdale/meshtastic-lite/tree/c143b82faf5d94e1bc29fdbcfa90b96c589f8e0a), pinned
to commit `c143b82faf5d94e1bc29fdbcfa90b96c589f8e0a` (BSD 3-Clause). This core
uses caller-selected CAD parameters and attempt-based windows, caps delay to
the 500 ms contention period, and includes no Meshtastic firmware or GPL code.

Target builds use OpenWrt's mbedTLS (`libmbedtls`/`libmbedcrypto`) and zlib.
Native tests may define `NETWORK_TEST_USE_OPENSSL` to use OpenSSL 3 for HMAC
when mbedTLS headers are unavailable on the host.
