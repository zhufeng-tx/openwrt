include $(TOPDIR)/rules.mk

PKG_NAME:=wltp
PKG_VERSION:=1.0
PKG_RELEASE:=1

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk

define Package/wltp
  SECTION:=net
  CATEGORY:=Network
  TITLE:=Wireless Lighting Throughput Profiler
endef

define Package/wltp/description
  WLTP is a wireless lighting protocol throughput tester for Art-Net, sACN,
  OSC, MA-Net2, RTP-MIDI, PSN, Kling-Net, CITP, and KiNET traffic.
endef

define Build/Prepare
	$(call Build/Prepare/Default)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR) \
		CC="$(TARGET_CC)" \
		CFLAGS="$(TARGET_CFLAGS)" \
		LDFLAGS="$(TARGET_LDFLAGS)"
endef

define Package/wltp/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/wltp $(1)/usr/bin/wltp
endef

$(eval $(call BuildPackage,wltp))
