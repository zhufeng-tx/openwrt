# Devboard UART bring-up notes

## Serial adapters on this Mac

- CP2104 onboard console bridge: `/dev/cu.usbserial-00F9462F`
- FT232 external USB-UART adapter: `/dev/cu.usbserial-A10LLYOY`
- Do not use `/dev/cu.wlan-debug`; it is an internal Apple debug serial node, not the FT232.

## Board UART mapping

- UART0 console: `/dev/ttyS0`
- UART1: `/dev/ttyS1`
- UART2: `/dev/ttyS2`
- Active target during testing: `ramips/mt76x8`, `devboard_wifi-test-board-hiwooya-16m`

## Firmware state

- Enabled BusyBox `stty` with `CONFIG_BUSYBOX_CONFIG_STTY=y`.
- Rebuilt `openwrt-ramips-mt76x8-devboard_wifi-test-board-hiwooya-16m-squashfs-sysupgrade.bin`.
- Flashed with `scripts/mcp-sysupgrade.py`.
- Verified after reboot that `/bin/stty -> busybox` exists and `stty` works.

## UART test results

- UART2 works with the FT232 at 9600 raw after setting the board side with `stty`.
- Proven receive token on `/dev/ttyS2`: `FT232-UART2-STTY-OK-1`
- UART1 appears unusable or not routed to the expected header pins:
  - `/dev/ttyS1` exists and accepts TX writes.
  - FT232 to UART1 RX produced `ttyS1 rx:0`.
  - UART1 TX to FT232 RX produced `0` bytes on the FT232.

## Network caution

- When the board is offline or frozen, `192.168.1.1` may reach the fibre modem instead.
- Before trusting board-side test results, verify MCP identity at `http://192.168.1.1:8765/mcp`.
- Correct board identity: MCP `initialize` returns `serverInfo.name = openwrt-mcpd`.
