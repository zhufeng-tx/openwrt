# SPDX-License-Identifier: GPL-2.0-only
include $(TOPDIR)/rules.mk

PKG_NAME:=remote-tester-radio
PKG_RELEASE:=2
PKG_LICENSE:=GPL-2.0-only AND BSD-3-Clause-Clear AND BSD-3-Clause AND MIT
PKG_LICENSE_FILES:=vendor/sx126x/LICENSE.txt vendor/RadioLib/LICENSE \
	vendor/RadioLib/src/modules/SX126x/patches/SX126x_patch_scan.h

include $(INCLUDE_DIR)/package.mk

define Package/remote-tester-radio
  SECTION:=utils
  CATEGORY:=Utilities
  TITLE:=SX1262 RadioLib PHY, diagnostics, and star-network daemon
  DEPENDS:=+libubus +libubox +libblobmsg-json +libuci +libgpiod +kmod-spi-dev +libstdcpp +libmbedtls +zlib +iperf3
endef

define Package/remote-tester-radio/description
SX1262 RadioLib PHY with local diagnostics, configured direct star-network
service, and authenticated iPerf control. Network TX is disabled by default and
requires explicit configuration plus antenna confirmation; diagnostic TX
remains separately gated.
endef

define Build/Prepare
	$(RM) -r $(PKG_BUILD_DIR)
	$(CP) ./src $(PKG_BUILD_DIR)
endef
define Build/Configure
endef
define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR) CC="$(TARGET_CC)" CXX="$(TARGET_CXX)" \
		TARGET_CPPFLAGS="$(TARGET_CPPFLAGS)" TARGET_CFLAGS="$(TARGET_CFLAGS)" \
		TARGET_CXXFLAGS="$(TARGET_CXXFLAGS)" TARGET_LDFLAGS="$(TARGET_LDFLAGS)"
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
