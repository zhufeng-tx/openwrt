#!/usr/bin/env python3
"""Run the isolated MT7628 IPv6 lab against a MikroTik RouterOS client.

The harness deliberately separates a read-only preflight from the mutating run.
It records a RouterOS snapshot before adding tagged temporary configuration and
always attempts restoration, including after an assertion or flash failure.
"""

import argparse
import base64
import contextlib
import datetime as dt
import getpass
import hashlib
import http.server
import ipaddress
import json
import os
from pathlib import Path
import pty
import re
import select
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import tty
import urllib.error
import urllib.parse
import urllib.request


TAG = "openwrt-ipv6-lab"
DEFAULT_PREFIX = "fd42:6970:7636:1::/64"
STATEFUL_PREFIX = "fd42:6970:7636:2::/64"
PD_PREFIX = "fd42:6970:7636::/48"
DEFAULT_IMAGE = (
    "bin/targets/ramips/mt76x8/"
    "openwrt-ramips-mt76x8-devboard_wifi-test-board-hiwooya-16m-"
    "ipv6-test-squashfs-sysupgrade.bin"
)
PROMPT_RE = re.compile(rb"root@[^:\r\n]+:[^\r\n]*# ")
BOOT_READY_RE = re.compile(
    rb"(?:root@[^:\r\n]+:[^\r\n]*# |Please press Enter to activate this console\.)"
)
USABLE_NEIGHBOR_STATES = ("REACHABLE", "STALE", "DELAY", "PROBE")


class LabError(RuntimeError):
    exit_code = 1


class AssertionFailure(LabError):
    pass


class PreflightError(LabError):
    exit_code = 2


class CleanupError(LabError):
    exit_code = 3


def utc_stamp():
    return dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def redact(value):
    """Return a JSON-safe copy with credential-like fields removed."""
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            lowered = str(key).lower()
            if any(word in lowered for word in ("password", "authorization", "secret")):
                result[key] = "<redacted>"
            else:
                result[key] = redact(item)
        return result
    if isinstance(value, list):
        return [redact(item) for item in value]
    return value


def boolish(value):
    return str(value).lower() in ("1", "true", "yes", "on")


def routeros_version(value):
    match = re.match(r"^(\d+)\.(\d+)", str(value or ""))
    if not match:
        raise PreflightError(f"could not parse RouterOS version: {value!r}")
    return tuple(int(part) for part in match.groups())


def extract_json(text):
    start = text.find("{")
    end = text.rfind("}")
    if start < 0 or end < start:
        raise LabError(f"command did not return JSON: {text.strip()}")
    try:
        return json.loads(text[start:end + 1])
    except json.JSONDecodeError as exc:
        raise LabError(f"invalid JSON from board: {exc}: {text.strip()}") from exc


def parse_firewall_packets(text):
    match = re.search(r"\bpackets\s+(\d+)\b", text)
    if not match:
        raise LabError(f"firewall rule counter not found: {text.strip()}")
    return int(match.group(1))


def client_observation_matches(status, mode, address):
    expected_method = "dhcpv6" if mode == "stateful" else "slaac"
    return (
        status.get("client_state") == "observed"
        and status.get("client_observed") is True
        and str(status.get("client_address", "")).lower() == address.lower()
        and status.get("client_method") == expected_method
        and status.get("client_neighbor_state") in USABLE_NEIGHBOR_STATES
        and status.get("dhcpv6_bound") == (mode == "stateful")
    )


def ra_matches(text, mode):
    lowered = text.lower()
    if "router advertisement" not in lowered:
        return False
    managed = "managed" in lowered
    other = "other stateful" in lowered or "other-config" in lowered
    autonomous = bool(re.search(r"\bauto(?:nomous)?\b", lowered))
    if mode in ("stateless", "stateless_pd"):
        return not managed and other and autonomous
    return managed and not other and not autonomous


def first_lan_prefix(prefix):
    network = ipaddress.IPv6Network(prefix)
    if network.prefixlen >= 64:
        return str(network)
    return str(next(network.subnets(new_prefix=64)))


def first_router_address(prefix):
    return str(ipaddress.IPv6Network(first_lan_prefix(prefix)).network_address + 1)


def address_in_prefix(address, prefix):
    try:
        return ipaddress.IPv6Interface(address).ip in ipaddress.IPv6Network(prefix)
    except ValueError:
        return False


def delegated_prefix_matches(prefix, aggregate):
    try:
        delegated = ipaddress.IPv6Network(prefix)
        pool = ipaddress.IPv6Network(aggregate)
    except ValueError:
        return False
    return delegated.prefixlen == 64 and delegated.subnet_of(pool) and str(delegated) != first_lan_prefix(aggregate)


def routeros_prefix(value):
    return str(value or "").split(",", 1)[0].strip().lower()


def ra_prefix_matches(text, lan_prefix, aggregate=None):
    lowered = text.lower()
    expected = str(ipaddress.IPv6Network(lan_prefix)).lower()
    advertised = re.findall(r"prefix info option.*?:\s*([0-9a-f:]+/\d+)", lowered)
    try:
        normalized = {str(ipaddress.IPv6Network(prefix)) for prefix in advertised}
    except ValueError:
        return False
    return normalized == {expected}


def parse_serial_frame(raw, marker):
    """Extract command output from a UART transcript that may echo input."""
    begin_token = marker + "_BEGIN"
    begin = raw.rfind(begin_token)
    rc_matches = list(re.finditer(re.escape(marker) + r"_RC=(\d+)", raw))
    if begin < 0 or not rc_matches:
        raise LabError(f"serial command timed out or lost framing: {raw[-500:]}")
    rc_match = rc_matches[-1]
    if rc_match.start() < begin:
        raise LabError(f"serial command returned malformed framing: {raw[-500:]}")
    output = raw[begin + len(begin_token):rc_match.start()].strip("\r\n")
    return output, int(rc_match.group(1))


def sysupgrade_failure(text):
    lowered = text.lower()
    for marker in (
        "failed to exec sysupgrade",
        "failed to exec upgraded",
        "sysupgrade aborted with return code",
        "sysupgrade stage 2 failed",
    ):
        if marker in lowered:
            return marker
    return None


def tio_command(device, baud):
    return [
        "tio", "-b", str(baud), "-d", "8", "-f", "none",
        "-s", "1", "-p", "none", "-n", "-c", "none", device,
    ]


class EventLog:
    def __init__(self, results_dir):
        self.results_dir = Path(results_dir)
        self.results_dir.mkdir(parents=True, exist_ok=True)
        self.events_path = self.results_dir / "events.jsonl"
        self.summary_path = self.results_dir / "summary.json"
        self.summary = {"started_at": utc_stamp(), "assertions": [], "status": "running"}

    def event(self, kind, **fields):
        record = {"at": utc_stamp(), "kind": kind, **redact(fields)}
        with self.events_path.open("a", encoding="utf-8") as output:
            output.write(json.dumps(record, sort_keys=True) + "\n")

    def assertion(self, name, passed, evidence=""):
        self.check(name, passed, evidence)
        if not passed:
            raise AssertionFailure(f"{name}: {evidence}")

    def check(self, name, passed, evidence=""):
        record = {"name": name, "passed": bool(passed), "evidence": str(evidence)}
        self.summary["assertions"].append(record)
        self.event("assertion", **record)
        self.flush()
        return bool(passed)

    def flush(self, status=None, error=None):
        if status:
            self.summary["status"] = status
        if error:
            self.summary["error"] = str(error)
        self.summary["updated_at"] = utc_stamp()
        self.summary_path.write_text(
            json.dumps(self.summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )


class RouterOSRest:
    def __init__(self, url, user, password, event_log=None, timeout=10.0):
        base = url.rstrip("/")
        self.base = base if base.endswith("/rest") else base + "/rest"
        token = base64.b64encode(f"{user}:{password}".encode()).decode()
        self.headers = {"Authorization": f"Basic {token}", "Accept": "application/json"}
        self.timeout = timeout
        self.event_log = event_log

    def request(self, method, path, payload=None):
        url = self.base + "/" + path.lstrip("/")
        data = None
        headers = dict(self.headers)
        if payload is not None:
            data = json.dumps(payload, separators=(",", ":")).encode()
            headers["Content-Type"] = "application/json"
        if self.event_log:
            self.event_log.event("router_request", method=method, path=path, payload=payload)
        request = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                body = response.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", "replace")
            if self.event_log:
                self.event_log.event(
                    "router_error", method=method, path=path, http_status=exc.code, body=body
                )
            raise LabError(f"RouterOS {method} {path}: HTTP {exc.code}: {body}") from exc
        except (urllib.error.URLError, TimeoutError, socket.timeout, OSError) as exc:
            if self.event_log:
                self.event_log.event("router_error", method=method, path=path, error=str(exc))
            raise PreflightError(f"RouterOS {method} {path} failed: {exc}") from exc
        result = json.loads(body) if body.strip() else {}
        if self.event_log:
            self.event_log.event("router_response", method=method, path=path, result=result)
        return result

    def get(self, path):
        return self.request("GET", path)

    def add(self, path, values):
        return self.request("PUT", path, values)

    def set(self, path, values):
        return self.request("PATCH", path, values)

    def remove(self, path, record_id):
        quoted = urllib.parse.quote(str(record_id), safe="*-")
        return self.request("DELETE", f"{path}/{quoted}")

    def command(self, path, values=None):
        return self.request("POST", path, values or {})


class SerialConsole:
    def __init__(self, device, baud=57600, log_path=None):
        self.device = device
        self.baud = baud
        self.log_path = Path(log_path) if log_path else None
        self.fd = None
        self.process = None
        self._counter = 0

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, *_args):
        self.close()

    def open(self):
        master, slave = pty.openpty()
        tty.setraw(slave)
        self.process = subprocess.Popen(
            tio_command(self.device, self.baud),
            stdin=slave,
            stdout=slave,
            stderr=slave,
            close_fds=True,
        )
        os.close(slave)
        self.fd = master
        os.set_blocking(self.fd, False)
        time.sleep(0.5)
        self.send_line("")
        data = self.read_until(PROMPT_RE, 15)
        if not PROMPT_RE.search(data):
            detail = data.decode("utf-8", "replace")[-500:]
            self.close()
            raise PreflightError(
                f"tio did not reach the serial prompt on {self.device} at {self.baud}: {detail}"
            )

    def close(self):
        if self.fd is None:
            return
        if self.process and self.process.poll() is None:
            with contextlib.suppress(OSError):
                os.write(self.fd, b"\x14q")
            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.process.terminate()
                try:
                    self.process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=2)
        os.close(self.fd)
        self.fd = None
        self.process = None

    def _log(self, data):
        if self.log_path and data:
            with self.log_path.open("ab") as output:
                output.write(data)

    def send_line(self, line):
        os.write(self.fd, line.encode() + b"\r")

    def read_until(self, pattern, timeout):
        deadline = time.monotonic() + timeout
        data = bytearray()
        while time.monotonic() < deadline:
            ready, _, _ = select.select([self.fd], [], [], min(0.25, deadline - time.monotonic()))
            if not ready:
                continue
            try:
                chunk = os.read(self.fd, 65536)
            except (BlockingIOError, OSError):
                if self.process and self.process.poll() is not None:
                    break
                continue
            if chunk:
                data.extend(chunk)
                self._log(chunk)
                if hasattr(pattern, "search") and pattern.search(data):
                    break
                if isinstance(pattern, bytes) and pattern in data:
                    break
        return bytes(data)

    def command(self, command, timeout=30):
        self._counter += 1
        marker = f"__IPV6_LAB_{os.getpid()}_{self._counter}"
        wrapped = (
            f"printf '\\n{marker}_BEGIN\\n'; {command}; __lab_rc=$?; "
            f"printf '\\n{marker}_RC=%s\\n' \"$__lab_rc\""
        )
        self.send_line(wrapped)
        deadline = time.monotonic() + timeout
        raw = ""
        last_error = None
        while time.monotonic() < deadline:
            chunk = self.read_until(PROMPT_RE, deadline - time.monotonic())
            if not chunk:
                break
            raw += chunk.decode("utf-8", "replace")
            try:
                return parse_serial_frame(raw, marker)
            except LabError as exc:
                # Background jobs and kernel messages can emit an unsolicited
                # prompt before the command echo and framing markers arrive.
                last_error = exc
        detail = last_error or LabError(f"serial command timed out: {raw[-500:]}")
        raise LabError(f"{detail}: command={command}")

    def flash_and_wait(self, image_path, sysupgrade_command="/sbin/sysupgrade", timeout=300):
        self.send_line(
            f"{shlex.quote(sysupgrade_command)} -n {shlex.quote(image_path)}"
        )
        raw = self.read_until(BOOT_READY_RE, timeout)
        if b"Please press Enter to activate this console." in raw and not PROMPT_RE.search(raw):
            self.send_line("")
            raw += self.read_until(PROMPT_RE, 30)
        if not PROMPT_RE.search(raw):
            raise LabError("board did not return to a root prompt after sysupgrade")
        text = raw.decode("utf-8", "replace")
        failure = sysupgrade_failure(text)
        if failure:
            raise LabError(f"sysupgrade did not write firmware: {failure}")
        return text


class ImageServer:
    def __init__(self, bind_address, image):
        self.bind_address = bind_address
        self.image = Path(image)
        self.tempdir = None
        self.httpd = None
        self.thread = None

    def __enter__(self):
        self.tempdir = tempfile.TemporaryDirectory(prefix="ipv6-lab-image-")
        served = Path(self.tempdir.name) / "firmware.bin"
        try:
            os.link(self.image, served)
        except OSError:
            shutil.copy2(self.image, served)

        directory = self.tempdir.name

        class QuietHandler(http.server.SimpleHTTPRequestHandler):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, directory=directory, **kwargs)

            def log_message(self, _format, *_args):
                return

        self.httpd = http.server.ThreadingHTTPServer((self.bind_address, 0), QuietHandler)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        return self

    @property
    def port(self):
        return self.httpd.server_address[1]

    def __exit__(self, *_args):
        if self.httpd:
            self.httpd.shutdown()
            self.httpd.server_close()
        if self.thread:
            self.thread.join(timeout=5)
        if self.tempdir:
            self.tempdir.cleanup()


def record_id(record):
    return record.get(".id") or record.get("id") or record.get("ret")


def place_before_first(items):
    values = records(items)
    return record_id(values[0]) if values else None


def records(value):
    if isinstance(value, list):
        return value
    if isinstance(value, dict) and value:
        return [value]
    return []


class IPv6Lab:
    def __init__(self, args, password):
        self.args = args
        self.log = EventLog(args.results_dir)
        self.router = RouterOSRest(args.router_url, args.router_user, password, self.log)
        self.serial = None
        self.snapshot = None
        self.flash_complete = False
        self.router_changed = False

    def write_snapshot(self, snapshot):
        path = self.log.results_dir / "router-before.json"
        path.write_text(json.dumps(redact(snapshot), indent=2, sort_keys=True) + "\n", encoding="utf-8")
        self.snapshot = snapshot
        return path

    def router_snapshot(self):
        paths = (
            "system/resource", "interface/ethernet", "interface/bridge/port",
            "ip/address", "ipv6/settings", "ipv6/address", "ipv6/route",
            "ipv6/dhcp-client", "ipv6/pool", "ip/dns", "ip/firewall/filter", "ip/firewall/nat",
        )
        return {path: self.router.get(path) for path in paths}

    def matching(self, path, key, value):
        return [item for item in records(self.router.get(path)) if item.get(key) == value]

    def preflight(self):
        image = Path(self.args.image).resolve()
        if not image.is_file():
            raise PreflightError(f"image not found: {image}")
        digest = sha256_file(image)
        self.log.summary["image"] = {"path": str(image), "bytes": image.stat().st_size, "sha256": digest}

        resource_items = records(self.router.get("system/resource"))
        if not resource_items:
            raise PreflightError("RouterOS system/resource returned no records")
        resource = resource_items[0]
        version = resource.get("version")
        if routeros_version(version) < (7, 1):
            raise PreflightError(f"RouterOS {version} does not provide the required REST API")

        ethernets = self.matching("interface/ethernet", "name", self.args.router_interface)
        if len(ethernets) != 1:
            raise PreflightError(f"expected one RouterOS interface named {self.args.router_interface}")
        ethernet = ethernets[0]
        if not boolish(ethernet.get("running", "false")):
            raise PreflightError(f"RouterOS {self.args.router_interface} is not running")

        bridge_ports = records(self.router.get("interface/bridge/port"))
        own_ports = [item for item in bridge_ports if item.get("interface") == self.args.router_interface]
        for own in own_ports:
            if boolish(own.get("disabled", "false")):
                continue
            bridge = own.get("bridge")
            peers = [
                item.get("interface") for item in bridge_ports
                if item.get("bridge") == bridge
                and item.get("interface") != self.args.router_interface
                and not boolish(item.get("disabled", "false"))
            ]
            if peers:
                if not self.args.allow_shared_bridge:
                    raise PreflightError(
                        f"{self.args.router_interface} shares bridge {bridge} with {', '.join(peers)}; "
                        "use --allow-shared-bridge only with --final-mode disabled"
                    )
                self.log.summary["shared_bridge"] = {"bridge": bridge, "peers": peers}

        conflicts = []
        for item in records(self.router.get("ip/address")):
            address = item.get("address", "")
            if address.startswith("192.168.1.") and item.get("interface") != self.args.router_interface:
                conflicts.append(f"{address} on {item.get('interface')}")
        if conflicts:
            raise PreflightError("RouterOS has conflicting 192.168.1.0/24 state: " + ", ".join(conflicts))

        for path in ("ipv6/dhcp-client", "ip/firewall/filter", "ip/firewall/nat", "ip/address"):
            stale = [
                item.get("comment") for item in records(self.router.get(path))
                if str(item.get("comment", "")).startswith(TAG)
            ]
            if stale:
                raise PreflightError(
                    f"RouterOS contains stale {TAG} records in {path}; restore or remove them before a new run"
                )

        serial_log = self.log.results_dir / "serial.log"
        self.serial = SerialConsole(self.args.serial, self.args.baud, serial_log)
        self.serial.open()
        board_text, rc = self.serial.command("ubus call system board")
        if rc:
            raise PreflightError("ubus board identity command failed")
        board = extract_json(board_text)
        if board.get("board_name") != "devboard,wifi-test-board-hiwooya-16m":
            raise PreflightError(f"unexpected board identity: {board.get('board_name')}")
        tools_text, rc = self.serial.command(
            "for p in uclient-fetch sha256sum sysupgrade; do command -v $p || exit 1; done; "
            "test -x /usr/libexec/validate_firmware_image"
        )
        if rc:
            raise PreflightError(f"board lacks required flash tools: {tools_text}")
        self.log.summary["router"] = {"version": version, "board-name": resource.get("board-name")}
        self.log.summary["board_before"] = board
        self.log.flush()
        return {"image": str(image), "sha256": digest, "router": resource, "board": board}

    def remove_tagged(self):
        for path in ("ipv6/dhcp-client", "ip/firewall/filter", "ip/firewall/nat", "ip/address"):
            for item in records(self.router.get(path)):
                if str(item.get("comment", "")).startswith(TAG):
                    item_id = record_id(item)
                    if item_id:
                        self.router.remove(path, item_id)

    def set_ipv6_setting(self, value):
        try:
            self.router.set("ipv6/settings", {"accept-router-advertisements": value})
        except LabError:
            self.router.command("ipv6/settings/set", {"accept-router-advertisements": value})

    def restore_router(self, snapshot=None):
        snapshot = snapshot or self.snapshot
        if not snapshot:
            return
        errors = []
        try:
            self.remove_tagged()
        except LabError as exc:
            errors.append(str(exc))

        before_ports = {
            record_id(item): item for item in records(snapshot.get("interface/bridge/port"))
            if item.get("interface") == self.args.router_interface and record_id(item)
        }
        for item_id, item in before_ports.items():
            try:
                self.router.set(
                    f"interface/bridge/port/{urllib.parse.quote(str(item_id), safe='*-')}",
                    {"disabled": item.get("disabled", "false")},
                )
            except LabError as exc:
                errors.append(str(exc))

        settings = records(snapshot.get("ipv6/settings"))
        if settings and "accept-router-advertisements" in settings[0]:
            try:
                self.set_ipv6_setting(settings[0]["accept-router-advertisements"])
            except LabError as exc:
                errors.append(str(exc))

        after = self.router_snapshot()
        (self.log.results_dir / "router-after.json").write_text(
            json.dumps(redact(after), indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        if errors:
            raise CleanupError("RouterOS restoration errors: " + "; ".join(errors))

    def capability_probe(self):
        failures = []
        for request_kind in ("address", "info", "prefix"):
            comment = f"{TAG}-cap-{request_kind}"
            try:
                values = {
                    "interface": self.args.router_interface,
                    "request": request_kind,
                    "use-peer-dns": "true",
                    "disabled": "true",
                    "comment": comment,
                }
                if request_kind == "prefix":
                    values.update({
                        "pool-name": f"{TAG}-cap-pd",
                        "pool-prefix-length": "64",
                        "prefix-hint": "::/64",
                    })
                self.router.add(
                    "ipv6/dhcp-client",
                    values,
                )
            except LabError as exc:
                failures.append(f"request={request_kind}: {exc}")
            finally:
                for item in self.matching("ipv6/dhcp-client", "comment", comment):
                    if record_id(item):
                        self.router.remove("ipv6/dhcp-client", record_id(item))
        if failures:
            raise PreflightError("RouterOS-only DHCPv6 capability check failed: " + "; ".join(failures))

    def disable_bridge_membership(self):
        for item in self.matching("interface/bridge/port", "interface", self.args.router_interface):
            if not boolish(item.get("disabled", "false")) and record_id(item):
                self.router.set(
                    f"interface/bridge/port/{urllib.parse.quote(str(record_id(item)), safe='*-')}",
                    {"disabled": "true"},
                )

    def management_interface(self):
        for item in records(self.router.get("ip/address")):
            if item.get("address", "").startswith(self.args.router_address + "/"):
                return item.get("interface")
        raise PreflightError(f"could not identify RouterOS interface for {self.args.router_address}")

    def prepare_flash_network(self, port):
        self.disable_bridge_membership()
        self.router.add(
            "ip/address",
            {
                "address": "192.168.1.254/24",
                "interface": self.args.router_interface,
                "comment": f"{TAG}-flash-address",
            },
        )

        management_interface = self.management_interface()
        common = {
            "chain": "forward", "action": "accept", "protocol": "tcp",
            "comment": f"{TAG}-flash-forward",
        }
        place_before = place_before_first(self.router.get("ip/firewall/filter"))
        if place_before:
            common["place-before"] = place_before
        self.router.add(
            "ip/firewall/filter",
            {**common, "src-address": "192.168.1.1", "dst-address": self.args.host_address,
             "dst-port": str(port)},
        )
        self.router.add(
            "ip/firewall/nat",
            {
                "chain": "srcnat", "action": "masquerade", "protocol": "tcp",
                "src-address": "192.168.1.1", "dst-address": self.args.host_address,
                "dst-port": str(port), "out-interface": management_interface,
                "comment": f"{TAG}-flash-nat",
            },
        )

    def prepare_sysupgrade_command(self):
        output, rc = self.serial.command(
            "test -x /lib/upgrade/stage2 && test -x /lib/upgrade/do_stage2"
        )
        if rc == 0:
            self.log.assertion("sysupgrade stage2 available", True, "/sbin/sysupgrade")
            return "/sbin/sysupgrade"

        patch_command = (
            "for script in stage2 do_stage2; do "
            "cp /lib/upgrade/$script /tmp/ipv6-lab-$script; "
            "chmod 0755 /tmp/ipv6-lab-$script; "
            "cp /tmp/ipv6-lab-$script /lib/upgrade/$script || exit 1; "
            "done; test -x /lib/upgrade/stage2 && test -x /lib/upgrade/do_stage2"
        )
        output, rc = self.serial.command(patch_command)
        self.log.assertion("sysupgrade executable bootstrap", rc == 0, output)
        return "/sbin/sysupgrade"

    def wait_board_image_ready(self, timeout=90):
        deadline = time.monotonic() + timeout
        last = ""
        while time.monotonic() < deadline:
            output, rc = self.serial.command(
                "test -x /usr/sbin/ipv6-test-mode && "
                "ubus list luci.ipv6_test 2>/dev/null && "
                "/usr/sbin/ipv6-test-mode status",
                timeout=15,
            )
            last = output
            try:
                status = extract_json(output)
            except LabError:
                status = {}
            if rc == 0 and "luci.ipv6_test" in output and status.get("ok") is True:
                return output
            time.sleep(2)
        raise AssertionFailure(f"timed out waiting for IPv6-test image readiness; last={last}")

    def flash(self, image, digest):
        with ImageServer(self.args.host_address, image) as server:
            self.prepare_flash_network(server.port)
            route_cmd = (
                f"ip route replace {shlex.quote(self.args.host_address)}/32 "
                "via 192.168.1.254 dev br-lan"
            )
            output, rc = self.serial.command(route_cmd)
            self.log.assertion("temporary board route", rc == 0, output)
            url = f"http://{self.args.host_address}:{server.port}/firmware.bin"
            output, rc = self.serial.command(
                f"rm -f /tmp/ipv6-lab-sysupgrade.bin; "
                f"uclient-fetch -O /tmp/ipv6-lab-sysupgrade.bin {shlex.quote(url)}",
                timeout=120,
            )
            self.log.assertion("firmware download", rc == 0, output[-500:])
            output, rc = self.serial.command("sha256sum /tmp/ipv6-lab-sysupgrade.bin")
            self.log.assertion("firmware SHA-256", rc == 0 and digest in output, output)
            output, rc = self.serial.command(
                "/usr/libexec/validate_firmware_image /tmp/ipv6-lab-sysupgrade.bin"
            )
            self.log.assertion("firmware platform validation", rc == 0, output)
            output, rc = self.serial.command("sysupgrade -T /tmp/ipv6-lab-sysupgrade.bin", timeout=60)
            self.log.assertion("sysupgrade test", rc == 0, output)
            sysupgrade_command = self.prepare_sysupgrade_command()
            boot_log = self.serial.flash_and_wait(
                "/tmp/ipv6-lab-sysupgrade.bin", sysupgrade_command
            )
            (self.log.results_dir / "flash-boot.log").write_text(boot_log, encoding="utf-8")
            self.flash_complete = True

        self.remove_tagged()
        output = self.wait_board_image_ready()
        self.log.assertion("new IPv6-test image booted", True, output)

    def board_rpc(self, method, values=None):
        payload = json.dumps(values or {}, separators=(",", ":"))
        output, rc = self.serial.command(
            f"ubus call luci.ipv6_test {shlex.quote(method)} {shlex.quote(payload)}",
            timeout=45,
        )
        if rc:
            raise LabError(f"board RPC {method} failed: {output}")
        return extract_json(output)

    def router_ethernet(self):
        matches = self.matching("interface/ethernet", "name", self.args.router_interface)
        if len(matches) != 1:
            raise LabError(f"lost RouterOS interface {self.args.router_interface}")
        return matches[0]

    def toggle_router_interface(self):
        item = self.router_ethernet()
        item_id = record_id(item)
        if not item_id:
            raise LabError("RouterOS ethernet record has no .id")
        path = f"interface/ethernet/{urllib.parse.quote(str(item_id), safe='*-')}"
        self.router.set(path, {"disabled": "true"})
        time.sleep(1)
        self.router.set(path, {"disabled": "false"})

    def start_ra_capture(self):
        command = (
            "rm -f /tmp/ipv6-lab-ra.txt /tmp/ipv6-lab-ra.pid; "
            "tcpdump -lnvv -c 1 -i br-lan 'icmp6 && ip6[40] == 134' "
            ">/tmp/ipv6-lab-ra.txt 2>&1 & echo $! >/tmp/ipv6-lab-ra.pid"
        )
        output, rc = self.serial.command(command)
        if rc:
            raise LabError(f"could not start RA capture: {output}")

    def finish_ra_capture(self, mode, lan_prefix, aggregate=None):
        time.sleep(5)
        output, _ = self.serial.command(
            "test ! -s /tmp/ipv6-lab-ra.pid || kill $(cat /tmp/ipv6-lab-ra.pid) 2>/dev/null; "
            "cat /tmp/ipv6-lab-ra.txt",
        )
        (self.log.results_dir / f"ra-{mode}.txt").write_text(output + "\n", encoding="utf-8")
        self.log.assertion(f"{mode} RA flags", ra_matches(output, mode), output)
        self.log.assertion(
            f"{mode} advertised LAN prefix",
            ra_prefix_matches(output, lan_prefix, aggregate),
            output,
        )

    def add_dhcp_client(self, request_kind, mode):
        self.remove_dhcp_clients()
        values = {
            "interface": self.args.router_interface,
            "request": request_kind,
            "use-peer-dns": "true",
            "disabled": "false",
            "comment": f"{TAG}-{mode}",
        }
        if request_kind == "prefix":
            values.update({
                "pool-name": f"{TAG}-pd",
                "pool-prefix-length": "64",
                "prefix-hint": "::/64",
            })
        self.router.add(
            "ipv6/dhcp-client",
            values,
        )

    def remove_dhcp_clients(self):
        for item in records(self.router.get("ipv6/dhcp-client")):
            if str(item.get("comment", "")).startswith(TAG) and record_id(item):
                self.router.remove("ipv6/dhcp-client", record_id(item))

    def wait_for(self, description, predicate, timeout=60):
        deadline = time.monotonic() + timeout
        last = None
        while time.monotonic() < deadline:
            last = predicate()
            if last:
                return last
            time.sleep(2)
        raise AssertionFailure(f"timed out waiting for {description}; last={last!r}")

    def poll_for(self, predicate, timeout=20):
        deadline = time.monotonic() + timeout
        last = None
        while time.monotonic() < deadline:
            last = predicate()
            if last:
                return last
            time.sleep(2)
        return last

    def prefix_address(self, prefix):
        for item in records(self.router.get("ipv6/address")):
            address = str(item.get("address", ""))
            if (
                item.get("interface") == self.args.router_interface
                and address_in_prefix(address, prefix)
            ):
                return item
        return None

    def default_route(self):
        for item in records(self.router.get("ipv6/route")):
            gateway = str(item.get("gateway", "")) + str(item.get("immediate-gw", ""))
            on_test_interface = (
                item.get("interface") == self.args.router_interface
                or self.args.router_interface in gateway
            )
            if (
                item.get("dst-address") in ("::/0", "0::/0")
                and boolish(item.get("active", "false"))
                and on_test_interface
            ):
                return item
        return None

    def dhcp_client_bound(self, mode, prefix, require_address):
        base = prefix.split("::", 1)[0].lower()
        for item in records(self.router.get("ipv6/dhcp-client")):
            acceptable_status = ("bound",) if require_address else ("bound", "idle")
            if (
                item.get("comment") != f"{TAG}-{mode}"
                or item.get("status") not in acceptable_status
            ):
                continue
            address = str(item.get("address", "")).lower()
            if require_address and not address.startswith(base + ":"):
                continue
            return item
        return None

    def pd_client_bound(self, aggregate):
        for item in records(self.router.get("ipv6/dhcp-client")):
            if item.get("comment") != f"{TAG}-stateless_pd" or item.get("status") != "bound":
                continue
            if delegated_prefix_matches(routeros_prefix(item.get("prefix")), aggregate):
                return item
        return None

    def pd_pool(self, delegated):
        for item in records(self.router.get("ipv6/pool")):
            if item.get("name") != f"{TAG}-pd":
                continue
            try:
                pool = ipaddress.IPv6Network(str(item.get("prefix", "")))
                lease = ipaddress.IPv6Network(delegated)
            except ValueError:
                continue
            if pool == lease and str(item.get("prefix-length", "64")) == "64":
                return item
        return None

    def dns_has(self, address):
        dns = records(self.router.get("ip/dns"))
        if not dns:
            return None
        dynamic = str(dns[0].get("dynamic-servers", "")).lower()
        return dns[0] if address.lower() in dynamic else None

    def router_ping(self, address):
        result = self.router.command(
            "ping", {"address": address, "count": "3", "interface": self.args.router_interface}
        )
        for item in records(result):
            status = str(item.get("status", "")).lower()
            if status == "echo reply":
                return True
        return False

    def router_resolve(self, name, expected):
        attempts = (("resolve", {"domain-name": name, "type": "ipv6"}),)
        for path, payload in attempts:
            try:
                value = self.router.command(path, payload)
            except LabError:
                continue
            if expected.lower() in json.dumps(value).lower():
                return True
        try:
            value = self.router.command("console", {"command": f':put [:resolve "{name}"]'})
            return expected.lower() in json.dumps(value).lower()
        except LabError:
            return False

    def firewall_packets(self):
        output, rc = self.serial.command(
            "nft -a list table inet fw4 | grep -F 'IPv6 test mode: block forwarded traffic'"
        )
        if rc:
            raise LabError(f"IPv6 forwarding rule not found: {output}")
        return parse_firewall_packets(output)

    def run_mode(self, mode, prefix, request_kind):
        failures = []
        status = self.board_rpc("apply", {"mode": mode, "prefix": prefix})
        self.log.assertion(f"{mode} board status", status.get("ok") is True, status)
        self.start_ra_capture()
        self.add_dhcp_client(request_kind, mode)
        self.toggle_router_interface()
        self.finish_ra_capture(mode, prefix)

        address = self.wait_for(f"{mode} RouterOS address", lambda: self.prefix_address(prefix))
        self.log.assertion(f"{mode} address", bool(address), address)
        dhcp = self.poll_for(
            lambda: self.dhcp_client_bound(mode, prefix, require_address=(mode == "stateful")),
        )
        if not self.log.check(
            f"{mode} DHCPv6 binding",
            bool(dhcp),
            dhcp or self.matching("ipv6/dhcp-client", "comment", f"{TAG}-{mode}"),
        ):
            failures.append(f"{mode} DHCPv6 binding")
        route = self.wait_for(f"{mode} default route", self.default_route)
        self.log.assertion(f"{mode} default route", bool(route), route)
        router_address = prefix.replace("::/64", "::1")
        dns = self.poll_for(lambda: self.dns_has(router_address))
        if not self.log.check(f"{mode} DNS learned", bool(dns), dns or self.router.get("ip/dns")):
            failures.append(f"{mode} DNS learned")
        if not self.log.check(f"{mode} local ICMPv6", self.router_ping(router_address), router_address):
            failures.append(f"{mode} local ICMPv6")
        if not self.log.check(
            f"{mode} local DNS resolution",
            self.router_resolve("router.ipv6.test", router_address),
            router_address,
        ):
            failures.append(f"{mode} local DNS resolution")

        client_address = str(address.get("address", "")).split("/", 1)[0]

        def observed_client():
            observation = self.board_rpc("get_status")
            return observation if client_observation_matches(
                observation, mode, client_address
            ) else None

        observation = self.wait_for(f"{mode} OpenWrt client observation", observed_client)
        self.log.assertion(f"{mode} OpenWrt client observation", True, observation)
        return failures

    def run_pd_mode(self, prefix):
        failures = []
        lan_prefix = first_lan_prefix(prefix)
        router_address = first_router_address(prefix)
        status = self.board_rpc("apply", {"mode": "stateless_pd", "prefix": prefix})
        self.log.assertion(
            "stateless_pd board status",
            status.get("ok") is True
            and status.get("mode") == "stateless_pd"
            and status.get("prefix") == prefix
            and status.get("lan_prefix") == lan_prefix
            and status.get("pd_server_enabled") is True,
            status,
        )
        self.start_ra_capture()
        self.add_dhcp_client("prefix", "stateless_pd")
        self.toggle_router_interface()
        self.finish_ra_capture("stateless_pd", lan_prefix, prefix)

        address = self.wait_for(
            "stateless_pd RouterOS SLAAC address",
            lambda: self.prefix_address(lan_prefix),
        )
        self.log.assertion("stateless_pd address", bool(address), address)
        dhcp = self.wait_for("stateless_pd IA_PD binding", lambda: self.pd_client_bound(prefix))
        self.log.assertion("stateless_pd IA_PD binding", True, dhcp)
        delegated = routeros_prefix(dhcp.get("prefix"))
        pool = self.wait_for("stateless_pd RouterOS dynamic pool", lambda: self.pd_pool(delegated))
        self.log.assertion("stateless_pd RouterOS dynamic pool", True, pool)

        def board_delegation():
            observation = self.board_rpc("get_status")
            return observation if (
                str(observation.get("delegated_prefix", "")).lower() == delegated
                and observation.get("pd_lease_count", 0) >= 1
                and observation.get("delegated_route_active") is True
            ) else None

        board_pd = self.wait_for("OpenWrt IA_PD lease and route", board_delegation)
        self.log.assertion("OpenWrt IA_PD lease and route", True, board_pd)
        route = self.wait_for("stateless_pd default route", self.default_route)
        self.log.assertion("stateless_pd default route", bool(route), route)
        if not self.log.check("stateless_pd local ICMPv6", self.router_ping(router_address), router_address):
            failures.append("stateless_pd local ICMPv6")

        client_address = str(address.get("address", "")).split("/", 1)[0]

        def observed_client():
            observation = self.board_rpc("get_status")
            return observation if client_observation_matches(
                observation, "stateless_pd", client_address
            ) else None

        observation = self.wait_for("stateless_pd OpenWrt client observation", observed_client)
        self.log.assertion("stateless_pd OpenWrt client observation", True, observation)
        return failures

    def run_scenarios(self):
        failures = []
        self.disable_bridge_membership()
        self.set_ipv6_setting("yes")

        activated = self.board_rpc("apply", {"mode": "stateless", "prefix": DEFAULT_PREFIX})
        self.log.assertion(
            "activate default stateless mode",
            activated.get("ok") is True and activated.get("mode") == "stateless",
            activated,
        )

        first = self.board_rpc("get_status")
        self.log.assertion(
            "first-boot services",
            all(first.get(key) is True for key in (
                "ok", "enabled", "address_active", "odhcpd_running",
                "dnsmasq_running", "firewall_running", "forwarding_blocked",
            )),
            first,
        )
        self.log.assertion("first-boot prefix", first.get("prefix") == DEFAULT_PREFIX, first)

        failures.extend(self.run_mode("stateless", DEFAULT_PREFIX, "info"))
        output, rc = self.serial.command("ip -6 route replace 2001:db8::/64 dev br-lan")
        self.log.assertion("forwarding test route", rc == 0, output)
        try:
            before = self.firewall_packets()
            external_ok = self.router_ping("2001:db8::1")
            time.sleep(1)
            after = self.firewall_packets()
        finally:
            self.serial.command("ip -6 route del 2001:db8::/64 dev br-lan 2>/dev/null || true")
        if not self.log.check("forwarded IPv6 rejected", not external_ok and after > before, f"{before}->{after}"):
            failures.append("forwarded IPv6 rejected")
        if not self.log.check(
            "local service survives reject",
            self.router_ping("fd42:6970:7636:1::1")
            and self.router_resolve("router.ipv6.test", "fd42:6970:7636:1::1"),
        ):
            failures.append("local service survives reject")

        failures.extend(self.run_pd_mode(PD_PREFIX))
        failures.extend(self.run_mode("stateful", STATEFUL_PREFIX, "address"))
        invalid = self.board_rpc("apply", {"mode": "stateless", "prefix": "2001:db8::/64"})
        current = self.board_rpc("get_status")
        self.log.assertion(
            "invalid prefix rollback",
            bool(invalid.get("error")) and current.get("mode") == "stateful"
            and current.get("prefix") == STATEFUL_PREFIX,
            {"invalid": invalid, "current": current},
        )

        disabled = self.board_rpc("disable")
        self.log.assertion(
            "disable mode",
            disabled.get("ok") is True and disabled.get("enabled") is False
            and disabled.get("active_mode") == "disabled"
            and disabled.get("client_state") == "disabled"
            and disabled.get("client_observed") is False
            and disabled.get("dhcpv6_bound") is False,
            disabled,
        )
        self.log.assertion("disabled router address unreachable", not self.router_ping("fd42:6970:7636:2::1"))

        if self.args.final_mode == "disabled":
            final = self.board_rpc("disable")
            self.log.assertion(
                "final disabled state",
                final.get("ok") is True and final.get("enabled") is False
                and final.get("active_mode") == "disabled",
                final,
            )
        else:
            final = self.board_rpc("apply", {"mode": "stateless", "prefix": DEFAULT_PREFIX})
            self.log.assertion(
                "final stateless state",
                final.get("ok") is True and final.get("mode") == "stateless"
                and final.get("prefix") == DEFAULT_PREFIX,
                final,
            )
        if failures:
            raise AssertionFailure("scenario failures: " + ", ".join(failures))

    def execute(self):
        try:
            preflight = self.preflight()
        except Exception as exc:
            if self.serial:
                self.serial.close()
            self.log.flush("preflight_failed", exc)
            raise
        if self.args.command == "preflight":
            if self.serial:
                self.serial.close()
            self.log.flush("passed")
            return

        self.snapshot = self.router_snapshot()
        self.write_snapshot(self.snapshot)
        self.router_changed = True
        primary_error = None
        cleanup_error = None
        try:
            self.capability_probe()
            if self.args.skip_flash:
                output, rc = self.serial.command(
                    "ubus list luci.ipv6_test; /usr/sbin/ipv6-test-mode status"
                )
                self.log.assertion(
                    "resume existing IPv6-test image",
                    rc == 0 and "luci.ipv6_test" in output,
                    output,
                )
                self.flash_complete = True
            else:
                self.flash(preflight["image"], preflight["sha256"])
            self.run_scenarios()
        except LabError as exc:
            primary_error = exc
        finally:
            if self.flash_complete:
                with contextlib.suppress(Exception):
                    if self.args.final_mode == "disabled":
                        self.board_rpc("disable")
                    else:
                        self.board_rpc("apply", {"mode": "stateless", "prefix": DEFAULT_PREFIX})
            if self.router_changed:
                try:
                    self.restore_router()
                except LabError as exc:
                    cleanup_error = exc
            if self.serial:
                self.serial.close()

        if cleanup_error:
            self.log.flush("cleanup_failed", cleanup_error)
            raise cleanup_error
        if primary_error:
            self.log.flush("failed", primary_error)
            raise primary_error
        self.log.flush("passed")


def load_snapshot(path):
    with open(path, encoding="utf-8") as source:
        return json.load(source)


def default_results_dir():
    return f"/private/tmp/ipv6-lab-{utc_stamp()}"


def add_common(parser):
    parser.add_argument("--router-url", default="http://192.168.50.1")
    parser.add_argument("--router-user", default="admin")
    parser.add_argument("--router-interface", default="ether2")
    parser.add_argument("--router-address", default="192.168.50.1")
    parser.add_argument("--host-address", default="192.168.50.2")
    parser.add_argument("--serial", required=True, help="currently enumerated /dev/cu.* device")
    parser.add_argument("--baud", type=int, default=57600)
    parser.add_argument("--image", default=DEFAULT_IMAGE)
    parser.add_argument("--results-dir", default=default_results_dir())
    parser.add_argument("--allow-insecure-http", action="store_true")
    parser.add_argument(
        "--allow-shared-bridge",
        action="store_true",
        help="temporarily isolate a port from a shared bridge; run requires --final-mode disabled",
    )


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    preflight = subparsers.add_parser("preflight", help="read-only device and topology checks")
    add_common(preflight)
    run = subparsers.add_parser("run", help="flash and execute the destructive live test")
    add_common(run)
    run.add_argument("--confirm-device-changes", action="store_true")
    run.add_argument("--final-mode", choices=("stateless", "disabled"), default="stateless")
    run.add_argument(
        "--skip-flash",
        action="store_true",
        help="resume tests on an already verified IPv6-test image",
    )
    restore = subparsers.add_parser("restore", help="restore RouterOS from a saved snapshot")
    restore.add_argument("--router-url", default="http://192.168.50.1")
    restore.add_argument("--router-user", default="admin")
    restore.add_argument("--router-interface", default="ether2")
    restore.add_argument("--snapshot", required=True)
    restore.add_argument("--results-dir", default=default_results_dir())
    restore.add_argument("--allow-insecure-http", action="store_true")
    return parser.parse_args(argv)


def password_from_environment():
    password = os.environ.get("MIKROTIK_PASSWORD")
    return password if password is not None else getpass.getpass("RouterOS password: ")


def enforce_transport(args):
    if args.router_url.startswith("http://") and not args.allow_insecure_http:
        raise PreflightError("plain HTTP requires --allow-insecure-http on this isolated lab")


def enforce_run_safety(args):
    if args.command == "run" and not args.confirm_device_changes:
        raise PreflightError("run requires --confirm-device-changes")
    if args.command == "run" and args.allow_shared_bridge and args.final_mode != "disabled":
        raise PreflightError("--allow-shared-bridge requires --final-mode disabled")


def main(argv=None):
    args = parse_args(argv)
    try:
        enforce_transport(args)
        password = password_from_environment()
        if args.command == "restore":
            log = EventLog(args.results_dir)
            router = RouterOSRest(args.router_url, args.router_user, password, log)
            shell_args = argparse.Namespace(**vars(args))
            shell_args.serial = ""
            shell_args.baud = 57600
            shell_args.image = DEFAULT_IMAGE
            shell_args.router_address = "192.168.50.1"
            shell_args.host_address = "192.168.50.2"
            lab = IPv6Lab(shell_args, password)
            lab.router = router
            lab.log = log
            lab.restore_router(load_snapshot(args.snapshot))
            log.flush("restored")
            return 0
        enforce_run_safety(args)
        IPv6Lab(args, password).execute()
        return 0
    except LabError as exc:
        print(f"ipv6-lab-test: {exc}", file=sys.stderr)
        return exc.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
