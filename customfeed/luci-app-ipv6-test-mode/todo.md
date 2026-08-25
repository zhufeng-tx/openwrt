# IPv6 test mode TODO

## `/80` downstream support with NDP proxying

Status: implemented and validated on the MT7628/RouterOS lab on 2026-08-25.

### Background

- The upstream allocation is assumed to be fd42:6970:7636::/48.
- The link between the main router and Device A currently uses
  fd42:6970:7636:1::/64.
- Device A uses fd42:6970:7636:1::a69/64 on that link.
- A proposed workaround assigns downstream devices addresses from
  fd42:6970:7636:1:a69::/80 and makes Device A proxy NDP for that range.

An /80 is a legal IPv6 routing prefix, but normal SLAAC expects a /64.
Clients in the proposed /80 would therefore need static addresses or a
stateful DHCPv6 design. This is an NDP-proxy workaround, not normal IPv6 prefix
delegation.

### Preferred design

If the main router can delegate or route another /64, use conventional IPv6
routing instead of NDP proxying:

    Device A uplink:       fd42:6970:7636:1::a69/64
    Device A downstream:   fd42:6970:7636:a69::/64
    Main-router route:     fd42:6970:7636:a69::/64
                           via fd42:6970:7636:1::a69

This allows ordinary Router Advertisements and SLAAC on the downstream LAN and
does not require NAT66.

### NDP proxy fallback

Consider ndppd only if the upstream router provides a single /64 and cannot
delegate another /64 or install a normal downstream route.

The proposed ndppd configuration is not sufficient by itself. A complete
design must include:

- The upstream interface on which the main router sends Neighbor Solicitations.
  This is the interface that belongs in the ndppd route block; it is not
  automatically br-lan.
- A separate downstream interface and an explicit route for
  fd42:6970:7636:1:a69::/80 toward it.
- IPv6 forwarding and the required firewall forwarding policy.
- Static or stateful DHCPv6 address assignment for downstream clients.
- Router Advertisement behavior for default-router information without
  incorrectly relying on /80 SLAAC.
- The ndppd package, configuration, init lifecycle, status reporting, and
  cleanup/rollback behavior.
- Verification that the upstream router accepts proxied NDP responses for the
  entire range.

Expected packet flow:

    Main router asks for a downstream address using NDP
        -> ndppd on Device A answers on the upstream interface
        -> the main router sends the packet to Device A
        -> Device A routes it through the downstream interface

### Implemented design

- The existing stateless and stateful `/64` modes remain unchanged.
- LuCI and RPC expose a separate experimental `ndp_proxy` mode with an
  upstream `/64` and a contained downstream `/80`.
- Device A uses `eth0.10` upstream and `eth0.20` downstream. `ndppd` listens on
  VLAN 10 and proxies the `/80` toward VLAN 20.
- `odhcpd` sends RA/default-router information with SLAAC disabled. A dedicated
  `dnsmasq-dhcpv6` process assigns IA_NA addresses from an explicit `/80` pool.
- IPv6 forwarding is allowed only between the two isolated test zones; legacy
  modes retain their forwarding REJECT rule.
- RouterOS uses VLAN 10 in `main`, VLAN 20 in an isolated VRF, and VLAN 30 for
  temporary LuCI management. A scheduler guard protects the control bridge.
- Apply, disable, boot, service failure, and harness failure paths restore the
  owned configuration and service state.

### Validation

The full live run passed 43 assertions. Evidence is in
`/private/tmp/ipv6-lab-ndppd-live-final`. The final flashed image then passed a
22-assertion focused proxy/cleanup run in `/private/tmp/ipv6-lab-ndppd-final2`.
The installed LuCI view asset was also verified through VLAN 30 in
`/private/tmp/ipv6-lab-ndppd-final-ui`. Together they include:

- `/80` IA_NA assignment and a lab-VRF default route.
- RA flags `M=1 A=0` with an on-link `/80` and no SLAAC.
- Neighbor Solicitation/Advertisement plus bidirectional ICMPv6 on both MT7628
  VLAN interfaces.
- Forwarding counter growth, LuCI reachability, invalid-prefix rollback, and a
  negative test where stopping `ndppd` breaks reachability.
- Final board-disabled state and restoration of RouterOS bridge/VLAN/VRF state.

Proof boundary: the downstream client is a RouterOS VRF on the same physical
router, not an external host. Packet captures on both board VLANs are therefore
required to reject local-delivery bypass.

### References

- https://openwrt.org/docs/guide-user/network/ipv6/configuration
- https://openwrt.org/docs/guide-user/network/ipv6/troubleshooting
- https://openwrt.org/docs/guide-user/network/ipv6/isp-configurations
