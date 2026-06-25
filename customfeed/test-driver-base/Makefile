include $(TOPDIR)/rules.mk

PKG_NAME:=test-driver-base
PKG_VERSION:=1
PKG_RELEASE:=2

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk

define Package/test-driver-base
  SECTION:=utils
  CATEGORY:=Utilities
  TITLE:=WiFi Test Driver Base
  DEPENDS:=
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
endef

define Build/Compile
endef

define Package/test-driver-base/install
	$(INSTALL_DIR) $(1)/test_ko
	$(INSTALL_DIR) $(1)/test_firmware
	$(INSTALL_DIR) $(1)/usr/libexec/rpcd
	$(INSTALL_BIN) ./files/test-driver.rpcd $(1)/usr/libexec/rpcd/luci.test_driver
endef

define Package/test-driver-base/postinst
#!/bin/sh
[ -n "$${IPKG_INSTROOT}" ] || killall -HUP rpcd 2>/dev/null || true
endef

$(eval $(call BuildPackage,test-driver-base))
