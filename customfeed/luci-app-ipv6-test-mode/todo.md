# IPv6 test mode TODO

## Implemented conventional prefix-delegation test

The `stateless_pd` mode now accepts a network-aligned ULA /48, /52, /56, or
/60. Netifd keeps the first /64 on the devboard LAN, odhcpd advertises that /64
with `A=1 O=1 M=0`, and downstream routers can request a distinct /64 with
DHCPv6 IA_PD. IA_NA remains disabled in this mode, so ordinary LAN hosts still
use SLAAC.

The RouterOS harness requests `prefix` with a /64 hint and verifies the bound
prefix, odhcpd lease visibility, and the devboard's downstream route. A real
client behind a separately identified RouterOS downstream interface is still
needed for end-to-end downstream SLAAC and traffic proof.

## Investigate /80 downstream support with NDP proxying

Status: investigation only; the proposed design is not yet approved for
implementation.

### Background

- The upstream allocation is assumed to be fd42:6970:7636::/48.
- The devboard is the main router. Its LAN currently uses and advertises
  fd42:6970:7636:1::/64.
- An ordinary LAN client receives or constructs one address in that /64 and
  does not create another subnet.
- The proposal applies only when Device A, connected to the devboard LAN, is
  itself a second router. Device A uses fd42:6970:7636:1::a69/64 on its uplink.
- A proposed workaround assigns downstream devices addresses from
  fd42:6970:7636:1:a69::/80 and makes Device A proxy NDP for that range.

The intended cascaded topology is therefore:

    Devboard/main router:  fd42:6970:7636:1::1/64
        -> Device A uplink: fd42:6970:7636:1::a69/64
        -> Device A downstream clients

An /80 is a legal IPv6 routing prefix, but normal SLAAC expects a /64.
Clients in the proposed /80 would therefore need static addresses or a
stateful DHCPv6 design. This is an NDP-proxy workaround, not normal IPv6 prefix
delegation.

### Preferred design

If the devboard can delegate or route another /64 to Device A, use conventional
IPv6 routing instead of NDP proxying:

    Device A uplink:       fd42:6970:7636:1::a69/64
    Device A downstream:   fd42:6970:7636:a69::/64
    Devboard route:        fd42:6970:7636:a69::/64
                           via fd42:6970:7636:1::a69

This allows ordinary Router Advertisements and SLAAC on the downstream LAN and
does not require NAT66.

### NDP proxy fallback

Consider ndppd only if the devboard provides Device A with the existing LAN
/64 but cannot delegate another /64 or install a normal downstream route.

`ndppd` belongs on Device A, because Device A must answer the devboard's
Neighbor Solicitations for clients hidden behind Device A. The devboard does
not need `ndppd` merely to advertise its current /64 to ordinary LAN clients.

Including `ndppd` in the devboard firmware is useful only if that same firmware
and hardware will also be used in the Device A/proxy-router role, if the
devboard will proxy between separate upstream and downstream interfaces in a
different topology, or if one common image is intentionally used for both
router roles. Otherwise the package is present but unused in the confirmed
devboard-as-main-router topology.

The proposed ndppd configuration is not sufficient by itself. A complete
design must include:

- Device A's upstream interface, on which the devboard sends Neighbor
  Solicitations.
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

    Devboard asks for a downstream address using NDP
        -> ndppd on Device A answers on the upstream interface
        -> the devboard sends the packet to Device A
        -> Device A routes it through the downstream interface

### Current /80 proxy implementation gaps

- Prefix validation accepts only ULA /64 prefixes.
- Address derivation and status checks assume a literal /64.
- The test topology currently has only the isolated br-lan test interface; it
  does not model separate upstream and downstream routed interfaces.
- The test mode deliberately installs an IPv6 forwarding REJECT rule.
- The devboard IPv6 test image profile includes ndppd, but the current
  devboard-as-main-router test mode neither needs nor configures it.
- No firmware/configuration ownership has been identified for Device A, which
  is the router that would actually run ndppd in the confirmed topology.

### Questions to resolve before implementation

1. Can the devboard delegate or statically route a separate downstream /64 to
   Device A instead of using NDP proxying?
2. What physical device is Device A, and does it run the same firmware image as
   the devboard?
3. Which Device A interface faces the devboard, and which interface contains
   Device A's downstream clients?
4. How should downstream clients receive addresses: static configuration or
   stateful DHCPv6?
5. Must existing /64-only test modes remain unchanged while NDP proxying is
   added as a separate mode?
6. Why was ndppd requested in the devboard firmware: will the devboard also be
   tested as Device A, or is a common image intended for both roles?
7. What RouterOS/OpenWrt packet captures and connectivity checks will be used
   as acceptance evidence?

### References

- https://openwrt.org/docs/guide-user/network/ipv6/configuration
- https://openwrt.org/docs/guide-user/network/ipv6/troubleshooting
- https://openwrt.org/docs/guide-user/network/ipv6/isp-configurations
