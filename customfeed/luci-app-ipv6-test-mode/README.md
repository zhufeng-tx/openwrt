# MikroTik IPv6 lab test

`scripts/ipv6-lab-test.py` validates this package on a Hiwooya 16M MT7628
board. MikroTik RouterOS `ether2` first acts as the legacy single-LAN IPv6
client, then carries an isolated VLAN/VRF topology for the NDP-proxy scenario.
The Mac is used only for RouterOS management, serial control, image serving,
LuCI access, and evidence collection; its network configuration is unchanged.

Serial automation is performed through the installed `tio` command using a
private PTY; the harness never opens the USB serial device itself.

## Safety model

- `preflight` is read-only and must pass before the script changes either
  device.
- `run` requires `--confirm-device-changes`. It flashes the board without
  preserving the old configuration and temporarily changes RouterOS.
- RouterOS records created by the harness use comments beginning with
  `openwrt-ipv6-lab`. The original `ether2` bridge state and IPv6 RA setting
  are saved before the first change and restored in a `finally` path.
- The harness refuses a shared `ether2` bridge by default. A disposable lab
  router may use `--allow-shared-bridge --final-mode disabled`; this isolates
  `ether2` during testing, restores its bridge membership afterward, and leaves
  the board's IPv6 test mode disabled so test RAs cannot leak onto the bridge.
- Plain HTTP uses Basic authentication and requires `--allow-insecure-http`.
  Supply the password through `MIKROTIK_PASSWORD` or the interactive prompt;
  never place it in the command line or result files.
- Generated evidence is written below `/private/tmp` by default and must not be
  committed.

## Topology

```text
Mac en5 192.168.50.2 -- RouterOS 192.168.50.5
                                  |
                               ether2
                                  |
                         MT7628 br-lan
                                  |
                         USB serial 57600 8N1
```

The NDP-proxy scenario temporarily converts the RouterOS bridge to a guarded
VLAN-aware lab. `ether1` retains the untagged IPv4 control path. `ether2`
carries VLAN 10 upstream and VLAN 20 downstream, while its untagged traffic is
placed in management VLAN 30 so LuCI remains reachable:

```text
RouterOS main VRF fd42:6970:7636:1::1/64
    VLAN 10 -- MT7628 eth0.10 fd42:6970:7636:1::a69/64
                   ndppd
    VLAN 20 -- MT7628 eth0.20 fd42:6970:7636:1:a69::1/80
         |
RouterOS lab VRF stateful DHCPv6 client

RouterOS VLAN 30 192.168.1.254 -- untagged MT7628 br-lan 192.168.1.1
```

RouterOS must not have an explicit `/80` route on VLAN 10. It treats the whole
upstream `/64` as on-link, sends NDP for the downstream address, and relies on
`ndppd` to answer before Device A routes the packet through VLAN 20.

`odhcpd` provides Router Advertisements and the default-router signal with
SLAAC disabled. A dedicated `dnsmasq-dhcpv6` instance assigns IA_NA addresses
from the explicit `/80` range; the system dnsmasq instance remains responsible
for local DNS only.

The board is expected at `192.168.1.1` before flashing. The harness gives
RouterOS `ether2` a temporary `192.168.1.254/24` address and creates narrowly
scoped forwarding/NAT rules so the board can download the exact image from a
bounded HTTP server on the Mac. It verifies the image hash and both
`validate_firmware_image` and `sysupgrade -T` before `sysupgrade -n`.

## Usage

Enumerate the current serial device instead of reusing an old adapter path:

```sh
find /dev -maxdepth 1 -type c -name 'cu.usb*' -print
```

Build the selected profile with GNU make, then run read-only preflight:

```sh
gmake -j"$(sysctl -n hw.ncpu)"
python3 scripts/ipv6-lab-test.py preflight \
  --router-url http://192.168.50.5 \
  --router-address 192.168.50.5 \
  --serial /dev/cu.usbserial-CURRENT \
  --allow-shared-bridge \
  --allow-insecure-http
```

Only after reviewing preflight, execute the live test:

```sh
python3 scripts/ipv6-lab-test.py run \
  --router-url http://192.168.50.5 \
  --router-address 192.168.50.5 \
  --serial /dev/cu.usbserial-CURRENT \
  --allow-insecure-http \
  --allow-shared-bridge \
  --confirm-device-changes
```

For an explicitly authorized shared bridge on a disposable test router:

```sh
python3 scripts/ipv6-lab-test.py run \
  --serial /dev/cu.usbserial-CURRENT \
  --allow-insecure-http \
  --allow-shared-bridge \
  --final-mode disabled \
  --confirm-device-changes
```

The run fails before flashing if RouterOS cannot create disabled DHCPv6
clients with both `request=info` and `request=address`. Prefix delegation is
not substituted for IA_NA address assignment.

If automatic cleanup reports exit code 3, retain the evidence directory and
restore from its snapshot:

```sh
python3 scripts/ipv6-lab-test.py restore \
  --snapshot /private/tmp/ipv6-lab-TIMESTAMP/router-before.json \
  --allow-insecure-http
```

After a separately verified flash, resume only the IPv6 scenarios with
`--skip-flash`. The harness still verifies the installed RPC/helper before it
enables test mode, and it isolates `ether2` first.

## Acceptance scenarios

The harness exercises first-boot service health, stateless RA plus DHCPv6
information, stateful DHCPv6 IA_NA, local DNS (`router.ipv6.test`), legacy
forwarding rejection, and the routed NDP-proxy mode. Proxy acceptance requires
an IA_NA address from `fd42:6970:7636:1:a69::/80`, RA flags `M=1 A=0`, NDP and
bidirectional ICMPv6 evidence on both MT7628 VLANs, firewall counter growth,
and a negative test with `ndppd` stopped. A RouterOS ping without matching
traffic on both board VLANs is treated as VRF-local bypass and fails.

The normal final state is disabled. RouterOS bridge, VLAN, VRF, address, and
firewall state is restored in `finally`; the flashed test firmware remains on
the board. Evidence is retained below the selected results directory.

Run host-side tests with:

```sh
python3 -B -m unittest discover -s scripts/tests -p 'test_ipv6_lab_test.py'
```
