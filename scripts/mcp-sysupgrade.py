#!/usr/bin/env python3
#
# Upload and schedule an OpenWrt sysupgrade image through openwrt-mcpd.

import argparse
import base64
import glob
import hashlib
import json
import os
import socket
import sys
import time
import urllib.error
import urllib.request


DEFAULT_IMAGE_GLOB = "bin/targets/ramips/mt76x8/*sysupgrade.bin"


class McpError(RuntimeError):
    pass


class McpClient:
    def __init__(self, url, timeout=10.0):
        self.url = url
        self.timeout = timeout
        self.next_id = 1

    def request(self, method, params=None):
        payload = {
            "jsonrpc": "2.0",
            "id": self.next_id,
            "method": method,
        }
        self.next_id += 1
        if params is not None:
            payload["params"] = params

        data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        req = urllib.request.Request(
            self.url,
            data=data,
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            body = resp.read()
        obj = json.loads(body.decode("utf-8"))
        if "error" in obj:
            err = obj["error"]
            raise McpError(f"{method}: {err.get('message', err)}")
        return obj.get("result", {})

    def initialize(self):
        return self.request(
            "initialize",
            {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "mcp-sysupgrade.py", "version": "1.0"},
            },
        )

    def tool(self, name, arguments):
        result = self.request(
            "tools/call",
            {"name": name, "arguments": arguments},
        )
        if result.get("isError"):
            text = ""
            for item in result.get("content", []):
                if item.get("type") == "text":
                    text = item.get("text", "")
                    break
            raise McpError(f"{name}: {text or result.get('structuredContent')}")
        return result


def find_default_image():
    matches = glob.glob(DEFAULT_IMAGE_GLOB)
    if not matches:
        raise SystemExit(f"no sysupgrade image matched {DEFAULT_IMAGE_GLOB}")
    matches.sort(key=lambda p: os.stat(p).st_mtime, reverse=True)
    return matches[0]


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def mcp_url(args):
    if args.host.startswith("http://") or args.host.startswith("https://"):
        base = args.host.rstrip("/")
        endpoint = args.endpoint if args.endpoint.startswith("/") else "/" + args.endpoint
        return base + endpoint
    endpoint = args.endpoint if args.endpoint.startswith("/") else "/" + args.endpoint
    return f"http://{args.host}:{args.port}{endpoint}"


def print_tool_line(result):
    for item in result.get("content", []):
        if item.get("type") == "text":
            print(item.get("text", ""))
            return


def upload_image(client, image, upload_id, digest, chunk_size):
    total = os.path.getsize(image)
    print(f"begin upload: {upload_id} {total} bytes sha256={digest}")
    print_tool_line(
        client.tool(
            "firmware_upload_begin",
            {"upload_id": upload_id, "total_bytes": total, "sha256": digest},
        )
    )

    offset = 0
    last_report = 0
    with open(image, "rb") as f:
        while True:
            data = f.read(chunk_size)
            if not data:
                break
            encoded = base64.b64encode(data).decode("ascii")
            result = client.tool(
                "firmware_upload_chunk",
                {"upload_id": upload_id, "offset": offset, "data_base64": encoded},
            )
            offset += len(data)
            now = time.monotonic()
            if offset == total or now - last_report >= 1.0:
                print_tool_line(result)
                last_report = now


def validate_image(client, upload_id, keep_config):
    result = client.tool(
        "firmware_validate",
        {"upload_id": upload_id, "keep_config": keep_config},
    )
    print_tool_line(result)
    return result.get("structuredContent", {})


def flash_image(client, upload_id, keep_config, force):
    result = client.tool(
        "firmware_flash",
        {
            "upload_id": upload_id,
            "allow_reboot": True,
            "keep_config": keep_config,
            "force": force,
        },
    )
    print_tool_line(result)
    return result


def try_initialize(client):
    try:
        client.initialize()
        return True
    except (McpError, OSError, socket.timeout, TimeoutError, urllib.error.URLError, json.JSONDecodeError):
        return False


def wait_for_disconnect(client, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not try_initialize(client):
            print("MCP disconnected")
            return True
        time.sleep(1)
    print("MCP did not disconnect before timeout")
    return False


def wait_for_reconnect(client, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if try_initialize(client):
            print("MCP initialize succeeded after reboot")
            return True
        time.sleep(2)
    raise SystemExit("timed out waiting for MCP to return")


def parse_args(argv):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--host", default="192.168.1.1", help="MCP host or base URL")
    p.add_argument("--port", type=int, default=8765, help="MCP HTTP port")
    p.add_argument("--endpoint", default="/mcp", help="MCP endpoint path")
    p.add_argument("--image", help=f"sysupgrade image path, default newest {DEFAULT_IMAGE_GLOB}")
    p.add_argument("--validate-only", action="store_true", help="upload and validate, but do not flash")
    p.add_argument("--keep-config", action="store_true", help="keep OpenWrt config during sysupgrade")
    p.add_argument("--force", action="store_true", help="pass -F to sysupgrade when validation says forceable")
    p.add_argument("--chunk-size", type=int, default=64 * 1024, help="raw bytes per upload chunk")
    p.add_argument("--no-wait", action="store_true", help="do not wait for disconnect and reconnect after flash")
    p.add_argument("--wait-timeout", type=int, default=180, help="seconds to wait for disconnect/reconnect")
    return p.parse_args(argv)


def main(argv=None):
    args = parse_args(argv or sys.argv[1:])
    if args.chunk_size <= 0:
        raise SystemExit("--chunk-size must be positive")

    image = args.image or find_default_image()
    image = os.path.abspath(image)
    if not os.path.isfile(image):
        raise SystemExit(f"image not found: {image}")

    digest = sha256_file(image)
    upload_id = f"fw-{digest[:16]}"
    client = McpClient(mcp_url(args))

    print(f"connecting: {client.url}")
    client.initialize()
    upload_image(client, image, upload_id, digest, args.chunk_size)
    validation = validate_image(client, upload_id, args.keep_config)

    valid = bool(validation.get("valid"))
    forceable = bool(validation.get("forceable"))
    if not valid and not args.force:
        raise SystemExit("validation did not mark image valid; rerun with --force only if this is expected")
    if args.force and not forceable:
        raise SystemExit("validation did not mark image forceable")

    if args.validate_only:
        return 0

    flash_image(client, upload_id, args.keep_config, args.force)
    if not args.no_wait:
        wait_for_disconnect(client, min(45, args.wait_timeout))
        wait_for_reconnect(client, args.wait_timeout)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
