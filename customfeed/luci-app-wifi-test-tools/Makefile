include $(TOPDIR)/rules.mk

LUCI_TITLE:=WiFi Bandwidth Test Tools
LUCI_DEPENDS:=+luci-app-wifi-test +bw-test-bwc +hgic-tcp-test +hgic-udp-test +wltp
LUCI_PKGARCH:=all

PKG_LICENSE:=Apache-2.0

include $(TOPDIR)/feeds/luci/luci.mk

# call BuildPackage - OpenWrt buildroot signature
