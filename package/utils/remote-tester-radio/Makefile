# SPDX-License-Identifier: GPL-2.0-only
include $(TOPDIR)/rules.mk

PKG_NAME:=remote-tester-radio
PKG_RELEASE:=1
PKG_LICENSE:=GPL-2.0-only AND BSD-3-Clause-Clear
PKG_LICENSE_FILES:=vendor/sx126x/LICENSE.txt

include $(INCLUDE_DIR)/package.mk

define Package/remote-tester-radio
  SECTION:=utils
  CATEGORY:=Utilities
  TITLE:=SX1262 radio HAL and diagnostic daemon
  DEPENDS:=+libubus +libubox +libuci +libgpiod +kmod-spi-dev
endef

define Package/remote-tester-radio/description
Local-only SX1262 HAL and diagnostics daemon. TX is disabled by default and is
limited to the fixed diagnostic frame after an explicit antenna confirmation.
endef

define Build/Prepare
	$(RM) -r $(PKG_BUILD_DIR)
	$(CP) ./src $(PKG_BUILD_DIR)
endef
define Build/Configure
endef
define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR) CC="$(TARGET_CC)" CFLAGS="$(TARGET_CFLAGS)" TARGET_LDFLAGS="$(TARGET_LDFLAGS)"
endef
define Package/remote-tester-radio/conffiles
/etc/config/remote-tester-radio
endef
define Package/remote-tester-radio/install
	$(INSTALL_DIR) $(1)/usr/sbin $(1)/usr/bin $(1)/etc/init.d $(1)/etc/config
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/remote-tester-radio $(1)/usr/sbin/
	$(INSTALL_BIN) ./files/remote-tester-radio.init $(1)/etc/init.d/remote-tester-radio
	$(INSTALL_CONF) ./files/remote-tester-radio.config $(1)/etc/config/remote-tester-radio
	$(INSTALL_BIN) ./files/remote-tester-radio $(1)/usr/bin/remote-tester-radioctl
endef
$(eval $(call BuildPackage,remote-tester-radio))
