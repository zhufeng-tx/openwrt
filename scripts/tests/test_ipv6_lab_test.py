#!/usr/bin/env python3

import base64
import importlib.util
import json
from pathlib import Path
import tempfile
import threading
from types import SimpleNamespace
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


SCRIPT = Path(__file__).resolve().parents[1] / "ipv6-lab-test.py"
SPEC = importlib.util.spec_from_file_location("ipv6_lab_test", SCRIPT)
LAB = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LAB)


class ParserTests(unittest.TestCase):
    def test_routeros_version_accepts_release_suffix(self):
        self.assertEqual((7, 18), LAB.routeros_version("7.18.2 (stable)"))

    def test_routeros_version_rejects_unknown_value(self):
        with self.assertRaises(LAB.PreflightError):
            LAB.routeros_version("development")

    def test_extract_json_ignores_shell_framing(self):
        self.assertEqual(
            {"ok": True, "prefix": LAB.DEFAULT_PREFIX},
            LAB.extract_json("echoed command\r\n{\"ok\":true,\"prefix\":\"%s\"}\r\nprompt" % LAB.DEFAULT_PREFIX),
        )

    def test_firewall_counter(self):
        self.assertEqual(42, LAB.parse_firewall_packets("counter packets 42 bytes 3528 comment test"))

    def test_client_observation_matches_each_assignment_mode(self):
        address = "fd42:6970:7636:1::1234"
        stateless = {
            "client_state": "observed",
            "client_observed": True,
            "client_address": address.upper(),
            "client_method": "slaac",
            "client_neighbor_state": "STALE",
            "dhcpv6_bound": False,
        }
        stateful = dict(stateless)
        stateful.update({"client_method": "dhcpv6", "dhcpv6_bound": True})
        self.assertTrue(LAB.client_observation_matches(stateless, "stateless", address))
        self.assertTrue(LAB.client_observation_matches(stateful, "stateful", address))
        self.assertTrue(LAB.client_observation_matches(stateful, "ndp_proxy", address))

    def test_client_observation_rejects_unusable_or_unbound_evidence(self):
        status = {
            "client_state": "observed",
            "client_observed": True,
            "client_address": "fd42:6970:7636:2::2b2",
            "client_method": "dhcpv6",
            "client_neighbor_state": "FAILED",
            "dhcpv6_bound": True,
        }
        self.assertFalse(
            LAB.client_observation_matches(status, "stateful", "fd42:6970:7636:2::2b2")
        )
        status["client_neighbor_state"] = "REACHABLE"
        status["dhcpv6_bound"] = False
        self.assertFalse(
            LAB.client_observation_matches(status, "stateful", "fd42:6970:7636:2::2b2")
        )

    def test_firewall_placement_uses_real_record_id_only(self):
        self.assertIsNone(LAB.place_before_first([]))
        self.assertEqual("*A", LAB.place_before_first([{".id": "*A"}]))

    def test_ra_mode_matching(self):
        stateless = "router advertisement, Flags [other stateful], prefix option Flags [onlink, auto]"
        stateful = "router advertisement, Flags [managed], prefix option Flags [onlink]"
        self.assertTrue(LAB.ra_matches(stateless, "stateless"))
        self.assertFalse(LAB.ra_matches(stateless, "stateful"))
        self.assertTrue(LAB.ra_matches(stateful, "stateful"))
        self.assertFalse(LAB.ra_matches(stateful, "stateless"))
        self.assertTrue(LAB.ra_matches(stateful, "ndp_proxy"))

    def test_proxy_capture_requires_ndp_and_bidirectional_echo(self):
        upstream = "neighbor solicitation\nneighbor advertisement\necho request\necho reply"
        downstream = "echo request\necho reply"
        self.assertTrue(LAB.proxy_capture_matches(upstream, downstream))
        self.assertFalse(LAB.proxy_capture_matches("echo request\necho reply", downstream))

    def test_serial_frame_uses_emitted_marker_after_echoed_command(self):
        marker = "__IPV6_LAB_1_1"
        raw = (
            "printf '\\n%s_BEGIN\\n'; ubus call system board; "
            "printf '\\n%s_RC=%%s\\n'\r\n"
            "%s_BEGIN\r\n{\"ok\":true}\r\n%s_RC=0\r\nroot@OpenWrt:/# "
        ) % (marker, marker, marker, marker)
        self.assertEqual(("{\"ok\":true}", 0), LAB.parse_serial_frame(raw, marker))

    def test_serial_transport_is_tio_at_project_baud(self):
        command = LAB.tio_command("/dev/cu.usbserial-CURRENT", 57600)
        self.assertEqual("tio", command[0])
        self.assertIn("57600", command)
        self.assertEqual("/dev/cu.usbserial-CURRENT", command[-1])

    def test_serial_command_ignores_unsolicited_prompt(self):
        console = LAB.SerialConsole("/dev/cu.test")
        console.send_line = lambda _line: None
        marker = "__IPV6_LAB_%d_1" % __import__("os").getpid()
        chunks = iter(
            [
                b"[1]+ Done tcpdump\r\nroot@OpenWrt:/# ",
                (
                    marker + "_BEGIN\r\nresult\r\n" + marker
                    + "_RC=0\r\nroot@OpenWrt:/# "
                ).encode(),
            ]
        )
        console.read_until = lambda _pattern, _timeout: next(chunks, b"")
        self.assertEqual(("result", 0), console.command("true", timeout=1))

    def test_first_boot_activation_is_a_ready_condition(self):
        self.assertIsNotNone(LAB.BOOT_READY_RE.search(b"Please press Enter to activate this console."))
        self.assertIsNotNone(LAB.BOOT_READY_RE.search(b"root@OpenWrt:/# "))
        self.assertIsNotNone(LAB.BOOT_READY_RE.search(b"root@(none):/# "))

    def test_redaction_is_recursive(self):
        value = {"password": "bad", "nested": [{"Authorization": "Basic bad"}], "ok": 1}
        self.assertEqual(
            {"password": "<redacted>", "nested": [{"Authorization": "<redacted>"}], "ok": 1},
            LAB.redact(value),
        )


class RestHandler(BaseHTTPRequestHandler):
    requests = []

    def do_GET(self):
        self._reply()

    def do_PUT(self):
        self._reply()

    def do_PATCH(self):
        self._reply()

    def do_DELETE(self):
        self._reply()

    def _reply(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length) if length else b""
        self.__class__.requests.append(
            {
                "method": self.command,
                "path": self.path,
                "authorization": self.headers.get("Authorization"),
                "body": json.loads(body) if body else None,
            }
        )
        payload = b'[{".id":"*1","version":"7.18.2"}]'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, _format, *_args):
        return


class RestClientTests(unittest.TestCase):
    def setUp(self):
        RestHandler.requests = []
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), RestHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

    def client(self):
        url = "http://127.0.0.1:%d" % self.server.server_address[1]
        return LAB.RouterOSRest(url, "admin", "secret")

    def test_rest_method_mapping_and_authentication(self):
        client = self.client()
        client.get("system/resource")
        client.add("ipv6/dhcp-client", {"request": "address"})
        client.set("ipv6/settings", {"accept-router-advertisements": "yes"})
        client.remove("ipv6/dhcp-client", "*1")
        self.assertEqual(["GET", "PUT", "PATCH", "DELETE"], [r["method"] for r in RestHandler.requests])
        expected = "Basic " + base64.b64encode(b"admin:secret").decode()
        self.assertTrue(all(r["authorization"] == expected for r in RestHandler.requests))
        self.assertEqual("/rest/ipv6/dhcp-client/*1", RestHandler.requests[-1]["path"])

    def test_event_log_never_receives_authorization_header(self):
        with tempfile.TemporaryDirectory() as directory:
            event_log = LAB.EventLog(directory)
            url = "http://127.0.0.1:%d" % self.server.server_address[1]
            client = LAB.RouterOSRest(url, "admin", "secret", event_log)
            client.get("system/resource")
            contents = (Path(directory) / "events.jsonl").read_text(encoding="utf-8")
            self.assertNotIn("secret", contents)
            self.assertNotIn("Basic", contents)

    def test_transport_failure_is_recorded(self):
        with tempfile.TemporaryDirectory() as directory:
            event_log = LAB.EventLog(directory)
            client = LAB.RouterOSRest("http://127.0.0.1:1", "admin", "secret", event_log, timeout=0.1)
            with self.assertRaises(LAB.PreflightError):
                client.get("system/resource")
            contents = (Path(directory) / "events.jsonl").read_text(encoding="utf-8")
            self.assertIn('"kind": "router_error"', contents)


class CliSafetyTests(unittest.TestCase):
    def test_plain_http_requires_explicit_opt_in(self):
        args = type("Args", (), {"router_url": "http://192.168.50.1"})()
        args.allow_insecure_http = False
        with self.assertRaises(LAB.PreflightError):
            LAB.enforce_transport(args)

    def test_https_does_not_require_insecure_flag(self):
        args = type("Args", (), {"router_url": "https://192.168.50.1"})()
        args.allow_insecure_http = False
        LAB.enforce_transport(args)

    def test_shared_bridge_run_requires_disabled_final_mode(self):
        args = LAB.parse_args(
            [
                "run", "--serial", "/dev/cu.test", "--allow-shared-bridge",
                "--confirm-device-changes", "--final-mode", "stateless",
            ]
        )
        with self.assertRaises(LAB.PreflightError):
            LAB.enforce_run_safety(args)

    def test_shared_bridge_disabled_mode_parses(self):
        args = LAB.parse_args(
            [
                "run", "--serial", "/dev/cu.test", "--allow-shared-bridge",
                "--final-mode", "disabled", "--confirm-device-changes",
            ]
        )
        self.assertEqual("disabled", args.final_mode)
        LAB.enforce_run_safety(args)

    def test_run_defaults_to_restore_safe_topology(self):
        args = LAB.parse_args(["run", "--serial", "/dev/cu.test"])
        self.assertEqual("disabled", args.final_mode)
        self.assertEqual("ether1", args.router_control_interface)
        self.assertFalse(args.proxy_only)

    def test_proxy_only_debug_run_parses(self):
        args = LAB.parse_args(["run", "--serial", "/dev/cu.test", "--proxy-only", "--skip-flash"])
        self.assertTrue(args.proxy_only)
        self.assertTrue(args.skip_flash)


class FakeRouter:
    def __init__(self):
        self.data = {
            "system/resource": [{"version": "7.18.2"}],
            "interface/ethernet": [{".id": "*e", "name": "ether2", "disabled": "false"}],
            "interface/bridge": [
                {".id": "*br", "name": "test", "pvid": "1", "vlan-filtering": "false"}
            ],
            "interface/bridge/port": [
                {".id": "*b", "interface": "ether2", "bridge": "test", "disabled": "true"}
            ],
            "interface/bridge/vlan": [],
            "interface/vlan": [],
            "ip/vrf": [{".id": "*0", "name": "main"}],
            "routing/table": [{".id": "*0", "name": "main"}],
            "system/scheduler": [],
            "ip/address": [
                {".id": "*a", "address": "192.168.1.254/24", "comment": LAB.TAG + "-flash"}
            ],
            "ipv6/settings": [{"accept-router-advertisements": "yes"}],
            "ipv6/address": [],
            "ipv6/route": [],
            "ipv6/dhcp-client": [],
            "ipv6/neighbor": [],
            "ip/dns": [{}],
            "ip/firewall/filter": [],
            "ip/firewall/nat": [],
        }
        self.removed = []
        self.set_calls = []

    def get(self, path):
        return self.data[path]

    def remove(self, path, item_id):
        self.removed.append((path, item_id))
        self.data[path] = [item for item in self.data[path] if LAB.record_id(item) != item_id]
        return {}

    def set(self, path, values):
        self.set_calls.append((path, values))
        if path == "ipv6/settings":
            self.data[path][0].update(values)
        elif path.startswith("interface/bridge/port/"):
            self.data["interface/bridge/port"][0].update(values)
        elif path.startswith("interface/bridge/"):
            self.data["interface/bridge"][0].update(values)
        return {}


class PingRouter:
    def __init__(self, result):
        self.result = result

    def command(self, _path, _values):
        return self.result


class RestorationTests(unittest.TestCase):
    def test_nonfatal_check_records_failure_without_raising(self):
        with tempfile.TemporaryDirectory() as directory:
            event_log = LAB.EventLog(directory)
            self.assertFalse(event_log.check("expected failure", False, "evidence"))
            summary = json.loads((Path(directory) / "summary.json").read_text(encoding="utf-8"))
            self.assertFalse(summary["assertions"][0]["passed"])

    def test_restore_removes_only_tagged_records_and_restores_saved_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            args = SimpleNamespace(
                results_dir=directory,
                router_url="http://127.0.0.1",
                router_user="admin",
                router_interface="ether2",
                router_control_interface="ether1",
            )
            lab = LAB.IPv6Lab(args, "secret")
            fake = FakeRouter()
            lab.router = fake
            snapshot = {key: json.loads(json.dumps(value)) for key, value in fake.data.items()}
            snapshot["interface/bridge/port"][0]["disabled"] = "false"
            snapshot["ipv6/settings"][0]["accept-router-advertisements"] = "no"
            lab.restore_router(snapshot)
            self.assertIn(("ip/address", "*a"), fake.removed)
            self.assertIn(
                ("interface/bridge/port/*b", {"disabled": "false"}),
                fake.set_calls,
            )
            self.assertIn(("ipv6/settings", {"accept-router-advertisements": "no"}), fake.set_calls)

    def test_preflight_failure_writes_summary(self):
        with tempfile.TemporaryDirectory() as directory:
            args = SimpleNamespace(
                results_dir=directory,
                router_url="http://127.0.0.1",
                router_user="admin",
                router_interface="ether2",
                command="preflight",
            )
            lab = LAB.IPv6Lab(args, "secret")

            def fail():
                raise LAB.PreflightError("offline")

            lab.preflight = fail
            with self.assertRaises(LAB.PreflightError):
                lab.execute()
            summary = json.loads((Path(directory) / "summary.json").read_text(encoding="utf-8"))
            self.assertEqual("preflight_failed", summary["status"])
            self.assertEqual("offline", summary["error"])

    def test_stateless_information_client_accepts_routeros_idle_status(self):
        with tempfile.TemporaryDirectory() as directory:
            args = SimpleNamespace(
                results_dir=directory,
                router_url="http://127.0.0.1",
                router_user="admin",
                router_interface="ether2",
            )
            lab = LAB.IPv6Lab(args, "secret")
            fake = FakeRouter()
            fake.data["ipv6/dhcp-client"] = [
                {
                    ".id": "*d",
                    "comment": LAB.TAG + "-stateless",
                    "status": "idle",
                    "request": "info",
                }
            ]
            lab.router = fake
            self.assertIsNotNone(lab.dhcp_client_bound("stateless", LAB.DEFAULT_PREFIX, False))

    def test_ping_requires_echo_reply_not_icmp_error(self):
        with tempfile.TemporaryDirectory() as directory:
            args = SimpleNamespace(
                results_dir=directory,
                router_url="http://127.0.0.1",
                router_user="admin",
                router_interface="ether2",
            )
            lab = LAB.IPv6Lab(args, "secret")
            lab.router = PingRouter([{"status": "net unreachable", "host": "fd00::1", "time": "1ms"}])
            self.assertFalse(lab.router_ping("2001:db8::1"))
            lab.router = PingRouter([{"status": "echo reply", "host": "fd00::1", "time": "1ms"}])
            self.assertTrue(lab.router_ping("fd00::1"))


if __name__ == "__main__":
    unittest.main()
