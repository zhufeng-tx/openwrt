include $(TOPDIR)/rules.mk

PKG_NAME:=hgic-tools
PKG_VERSION:=1.0
PKG_RELEASE:=1

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk

define Package/hgic-tools/Default
  SECTION:=utils
  CATEGORY:=Utilities
  SUBMENU:=HGIC tools
endef

define Package/hgpriv
  $(call Package/hgic-tools/Default)
  TITLE:=HGIC wireless private ioctl tool
endef

define Package/hgota
  $(call Package/hgic-tools/Default)
  TITLE:=HGIC OTA firmware update tool
endef

define Package/hgic-netat
  $(call Package/hgic-tools/Default)
  TITLE:=HGIC network AT command tool
endef

define Package/hgic-tcp-test
  $(call Package/hgic-tools/Default)
  TITLE:=HGIC TCP test tool
endef

define Package/hgic-udp-test
  $(call Package/hgic-tools/Default)
  TITLE:=HGIC UDP test tool
endef

define Package/hgic-dsleep-test
  $(call Package/hgic-tools/Default)
  TITLE:=HGIC deep sleep test tool
endef

define Package/bw-test-bwc
  $(call Package/hgic-tools/Default)
  TITLE:=Bandwidth test statistics collector daemon
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR) \
		CC="$(TARGET_CC)" \
		CFLAGS="$(TARGET_CFLAGS) -D__linux__" \
		LDFLAGS="$(TARGET_LDFLAGS)"
endef

define Package/hgpriv/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/hgpriv $(1)/usr/bin/
endef

define Package/hgota/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/hgota $(1)/usr/bin/
endef

define Package/hgic-netat/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/libnetat $(1)/usr/bin/
endef

define Package/hgic-tcp-test/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/tcp_test $(1)/usr/bin/
endef

define Package/hgic-udp-test/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/udp_test $(1)/usr/bin/
endef

define Package/hgic-dsleep-test/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/dsleep_test $(1)/usr/bin/
endef

define Package/bw-test-bwc/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/bw_test_bwc $(1)/usr/bin/bw-test-bwc
endef

$(eval $(call BuildPackage,hgpriv))
$(eval $(call BuildPackage,hgota))
$(eval $(call BuildPackage,hgic-netat))
$(eval $(call BuildPackage,hgic-tcp-test))
$(eval $(call BuildPackage,hgic-udp-test))
$(eval $(call BuildPackage,hgic-dsleep-test))
$(eval $(call BuildPackage,bw-test-bwc))
