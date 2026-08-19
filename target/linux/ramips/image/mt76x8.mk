#
# MT76x8 Profiles
#

DEFAULT_SOC := mt7628an

define Device/devboard_wifi-test-board
  DEVICE_VENDOR := DevBoard
  DEVICE_MODEL := WiFi Test Board
  DEVICE_PACKAGES := -firewall4 -nftables -kmod-nft-offload -dnsmasq \
	-dropbear -odhcp6c -odhcpd-ipv6only -ppp -ppp-mod-pppoe \
	kmod-sdhci-mt7620 omcproxy kmod-spi-dev kmod-usb-core kmod-usb2 \
	tcpdump wltp
endef

define Device/devboard_wifi-test-board-8m
  $(Device/devboard_wifi-test-board)
  IMAGE_SIZE := 7872k
  DEVICE_VARIANT := 8M
endef
TARGET_DEVICES += devboard_wifi-test-board-8m

define Device/devboard_wifi-test-board-hiwooya-16m
  $(Device/devboard_wifi-test-board)
  IMAGE_SIZE := 16064k
  DEVICE_VARIANT := Hiwooya 16M
endef
TARGET_DEVICES += devboard_wifi-test-board-hiwooya-16m

define Device/devboard_wifi-test-board-hiwooya-16m-ipv6-test
  $(Device/devboard_wifi-test-board)
  IMAGE_SIZE := 16064k
  DEVICE_VARIANT := Hiwooya 16M IPv6 Test
  DEVICE_DTS := mt7628an_devboard_wifi-test-board-hiwooya-16m
  SUPPORTED_DEVICES := devboard,wifi-test-board-hiwooya-16m
  DEVICE_PACKAGES += firewall4 dnsmasq odhcpd-ipv6only luci-light \
	luci-app-ipv6-test-mode -wltp -openwrt-mcpd -hgpriv
endef
TARGET_DEVICES += devboard_wifi-test-board-hiwooya-16m-ipv6-test
