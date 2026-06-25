include $(TOPDIR)/rules.mk

PKG_NAME:=openwrt-mcpd
PKG_VERSION:=1.0
PKG_RELEASE:=1

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk

define Package/openwrt-mcpd
  SECTION:=net
  CATEGORY:=Network
  TITLE:=OpenWrt MCP development board daemon
  DEPENDS:=+libjson-c +libmicrohttpd-no-ssl +hgpriv
endef

define Package/openwrt-mcpd/description
  Full-access MCP HTTP daemon for OpenWrt development boards.
endef

define Build/Prepare
	$(call Build/Prepare/Default)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR) \
		CC="$(TARGET_CC)" \
		CFLAGS="$(TARGET_CFLAGS) $(TARGET_CPPFLAGS)" \
		LDFLAGS="$(TARGET_LDFLAGS)"
endef

define Package/openwrt-mcpd/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/openwrt-mcpd $(1)/usr/sbin/openwrt-mcpd
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/openwrt-mcpd.init $(1)/etc/init.d/openwrt-mcpd
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/openwrt-mcpd.config $(1)/etc/config/openwrt-mcpd
endef

$(eval $(call BuildPackage,openwrt-mcpd))
