include $(TOPDIR)/rules.mk

LUCI_TITLE:=Isolated IPv6 Test Mode
LUCI_DESCRIPTION:=Configure an offline LAN for SLAAC-only, stateful, and DHCPv6-PD testing
LUCI_DEPENDS:=+luci-light +odhcpd-ipv6only +dnsmasq +firewall4
LUCI_PKGARCH:=all

PKG_LICENSE:=Apache-2.0

define Package/luci-app-ipv6-test-mode/conffiles
/etc/config/ipv6test
endef

include $(TOPDIR)/feeds/luci/luci.mk

# call BuildPackage - OpenWrt buildroot signature
