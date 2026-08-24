# IPv6 test mode TODO

## Investigate /80 downstream support with NDP proxying

Status: investigation only; the proposed design is not yet approved for
implementation.

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

### Current implementation gaps

- Prefix validation accepts only ULA /64 prefixes.
- Address derivation and status checks assume a literal /64.
- The test topology currently has only the isolated br-lan test interface; it
  does not model separate upstream and downstream routed interfaces.
- The test mode deliberately installs an IPv6 forwarding REJECT rule.
- The IPv6 test image profile includes ndppd, but the test mode has no ndppd
  service configuration or lifecycle integration.

### Questions to resolve before implementation

1. Is NDP proxying required because the upstream router supplies only one /64,
   or can it delegate/route a separate downstream /64?
2. Which concrete interface faces the upstream router, and which interface
   contains the downstream clients?
3. How should downstream clients receive addresses: static configuration or
   stateful DHCPv6?
4. Must existing /64-only test modes remain unchanged while NDP proxying is
   added as a separate mode?
5. What RouterOS/OpenWrt packet captures and connectivity checks will be used
   as acceptance evidence?

### References

- https://openwrt.org/docs/guide-user/network/ipv6/configuration
- https://openwrt.org/docs/guide-user/network/ipv6/troubleshooting
- https://openwrt.org/docs/guide-user/network/ipv6/isp-configurations
