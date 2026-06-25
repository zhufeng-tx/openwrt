include $(TOPDIR)/rules.mk

LUCI_TITLE:=LuCI Support for WiFi Test FMAC Config
LUCI_DEPENDS:=+luci-app-wifi-test +hgpriv +wpad-basic-mbedtls
LUCI_PKGARCH:=all

PKG_LICENSE:=Apache-2.0

include $(TOPDIR)/feeds/luci/luci.mk

# call BuildPackage - OpenWrt buildroot signature
