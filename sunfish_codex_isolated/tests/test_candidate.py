"""Local fake-server tests only: no live HA requests and no account credentials."""

import http.client
import io
import json
import sys
import threading
import unittest
from types import SimpleNamespace
from unittest.mock import patch
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1]))
from mcp_proxy import (ALLOWED_TOOLS, PolicyError, check_request, filter_response,
                       make_server, read_rpc_response, scrub)
from security import identity_allowed, render_nginx_config, validate_user_id
from readiness import (ReadinessError, mount_boundary_ok, run_check,
                       sandbox_command, userns_command, namespace_identity_ok)


class IngressIdentityTests(unittest.TestCase):
    OWNER = "a1" * 16

    def test_configuration_id_is_mandatory_and_strict(self):
        for value in (None, "", self.OWNER.upper(), self.OWNER + "\n", "a" * 31,
                      "g" * 32, self.OWNER + "; allow all;", 7):
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_user_id(value)
        self.assertEqual(validate_user_id(self.OWNER), self.OWNER)

    def test_missing_other_and_spoof_style_identity_denied(self):
        for header in (None, "", "b2" * 16, self.OWNER.upper(), self.OWNER + "\n",
                       self.OWNER + "," + self.OWNER, " " + self.OWNER,
                       "X-Remote-User-Id: " + self.OWNER):
            with self.subTest(header=header):
                self.assertFalse(identity_allowed(header, self.OWNER))
        self.assertTrue(identity_allowed(self.OWNER, self.OWNER))

    def test_nginx_generation_preserves_network_and_fail_closed_gates(self):
        template = (Path(__file__).parents[1] / "nginx.conf").read_text()
        rendered = render_nginx_config(template, self.OWNER)
        self.assertIn("~^" + self.OWNER + "$ 1;", rendered)
        self.assertIn("default 0;", rendered)
        self.assertIn("if ($codex_allowed_user = 0) { return 403; }", rendered)
        self.assertIn("allow 172.30.32.2;", rendered)
        self.assertIn("deny all;", rendered)
        self.assertNotIn("__ALLOWED_USER_ID__", rendered)
        for unsafe_template in ("", template + "__ALLOWED_USER_ID__"):
            with self.assertRaises(ValueError):
                render_nginx_config(unsafe_template, self.OWNER)


class ReadinessTests(unittest.TestCase):
    def test_host_mounts_denied_without_logging_paths(self):
        base = "1 0 0:1 / / rw - overlay overlay rw\n2 1 0:2 / /data rw - ext4 /dev/mock rw"
        self.assertTrue(mount_boundary_ok(base))
        for mountpoint in ("/config", "/homeassistant", "/media", "/var/run/docker.sock", "/share/nested"):
            self.assertFalse(mount_boundary_ok(base + "\n3 1 0:3 / " + mountpoint + " rw - ext4 /dev/mock rw"))
        self.assertFalse(mount_boundary_ok("malformed"))

    def test_native_sandbox_and_user_namespace_are_unprivileged(self):
        command = sandbox_command()
        self.assertEqual(command[:4], ["/sbin/su-exec", "codex:codex", "/usr/local/bin/codex", "sandbox"])
        self.assertIn('sandbox_mode="workspace-write"', command)
        self.assertNotIn("linux", command)
        self.assertEqual(userns_command()[:3], ["/sbin/su-exec", "codex:codex", "/usr/local/bin/bwrap"])

    def test_process_start_errors_use_fixed_diagnostics(self):
        import subprocess
        cases = [
            (FileNotFoundError("private-secret"), "EXECUTABLE_NOT_FOUND"),
            (subprocess.TimeoutExpired("private-secret", 20), "PROCESS_TIMEOUT"),
            (OSError("private-secret"), "PROCESS_START_FAILED"),
        ]
        for error, category in cases:
            with self.subTest(category=category):
                def fail(*_a, **_k):
                    raise error
                with patch("builtins.print") as output, self.assertRaises(ReadinessError):
                    run_check("test", ["ignored"], {}, runner=fail)
                self.assertEqual(output.call_args.args[0], "Readiness failure category: " + category)
                self.assertNotIn("private-secret", str(output.call_args_list))
        self.assertIn("--unshare-user", userns_command())

    def test_readiness_is_bounded_and_fail_closed(self):
        def fail(_command, **kwargs):
            self.assertEqual(kwargs["timeout"], 20)
            self.assertEqual(kwargs["cwd"], "/data/workspace")
            self.assertEqual(kwargs["env"], {"HOME": "/safe"})
            return SimpleNamespace(returncode=1, stdout=b"secret must not be printed")
        with patch("builtins.print") as output, self.assertRaises(ReadinessError):
            run_check("test", ["ignored"], {"HOME": "/safe"}, runner=fail)
        self.assertEqual(output.call_args_list[0].args[0], "Readiness test: FAIL")
        self.assertEqual(output.call_args.args[0], "Readiness failure category: UNSPECIFIED_NONZERO_EXIT")

    def test_diagnostic_categories_do_not_emit_process_stderr(self):
        cases = {
            b"could not build map_hash": "NGINX_MAP_HASH_SIZE",
            b"unknown directive": "NGINX_UNKNOWN_DIRECTIVE",
            b"getpwnam failed": "NGINX_USER_LOOKUP",
            b"No such file or directory": "MISSING_RUNTIME_PATH",
            b"invalid configuration": "CONFIGURATION_SYNTAX",
            b"Operation not permitted": "OPERATION_NOT_PERMITTED",
        }
        for message, category in cases.items():
            with self.subTest(category=category):
                runner = lambda *_a, **_k: SimpleNamespace(returncode=1, stdout=b"", stderr=message + b" private-secret")
                with patch("builtins.print") as output, self.assertRaises(ReadinessError):
                    run_check("test", ["ignored"], {}, runner=runner)
                self.assertEqual(output.call_args.args[0], "Readiness failure category: " + category)
                self.assertNotIn("private-secret", str(output.call_args_list))

    def test_version_must_match_pinned_release(self):
        for version, success in ((b"codex-cli 0.160.0\n", True), (b"codex-cli 0.159.0\n", False)):
            runner = lambda *_a, **_k: SimpleNamespace(returncode=0, stdout=version)
            with patch("builtins.print"):
                if success:
                    run_check("version", ["ignored"], {}, runner=runner, version=True)
                else:
                    with self.assertRaises(ReadinessError):
                        run_check("version", ["ignored"], {}, runner=runner, version=True)

    def test_logged_out_terminal_does_not_start_device_auth(self):
        session = (Path(__file__).parents[1] / "codex-session").read_text()
        self.assertNotIn("    /usr/local/bin/codex login --device-auth", session)
        self.assertIn("exec /bin/bash --noprofile --norc", session)
        self.assertIn("umask 077", session)
        self.assertIn("--sandbox workspace-write", session)

    def test_namespace_local_root_is_only_unprivileged_container_identity(self):
        self.assertTrue(namespace_identity_ok(0, "0 1000 1\n"))
        self.assertTrue(namespace_identity_ok(1000, "1000 1000 1\n"))
        for mapping in ("0 0 1", "0 1000 65536", "0 1000 1\n1 0 1", "0 999 1", "malformed"):
            self.assertFalse(namespace_identity_ok(0, mapping))


def rpc(method, params=None):
    return {"jsonrpc": "2.0", "id": 7, "method": method, "params": params or {}}


class PolicyTests(unittest.TestCase):
    def test_only_explicit_read_tools(self):
        for tool in ALLOWED_TOOLS:
            self.assertEqual(check_request(rpc("tools/call", {"name": tool})), "tools/call")
        for tool in ("ha_call_service", "ha_set_entity", "ha_manage_app", "ha_manage_integration",
                     "ha_config_set_automation", "ha_restart", "ha_get_logs", "ha_get_app"):
            with self.subTest(tool=tool), self.assertRaises(PolicyError):
                check_request(rpc("tools/call", {"name": tool}))

    def test_batch_and_protocol_writes_denied(self):
        for message in ([rpc("ping")], rpc("tasks/cancel"), rpc("sampling/createMessage"),
                        rpc("tools/call", {"name": "ha_get_state", "arguments": []})):
            with self.assertRaises(PolicyError):
                check_request(message)

    def test_skill_path_traversal_denied(self):
        for uri in ("file:///data/options.json", "skill://home-assistant-best-practices/../../secret",
                    "skill://home-assistant-best-practices/references/../SKILL.md"):
            with self.assertRaises(PolicyError):
                check_request(rpc("resources/read", {"uri": uri}))
        with self.assertRaises(PolicyError):
            check_request(rpc("tools/call", {"name": "ha_get_skill_guide", "arguments": {"file": "/data/options.json"}}))
        check_request(rpc("resources/read", {"uri": "skill://home-assistant-best-practices/SKILL.md"}))
        check_request(rpc("tools/call", {"name": "ha_get_skill_guide", "arguments": {"file": "references/safe-refactoring.md"}}))

    def test_discovery_hides_write_tools(self):
        message = {"result": {"tools": [{"name": "ha_search"}, {"name": "ha_manage_app"}]}}
        self.assertEqual(filter_response(message, "tools/list")["result"]["tools"], [{"name": "ha_search"}])

    def test_secret_output_scrubbing(self):
        secret = "http://private.invalid/private-secret-abcdefgh/mcp"
        value = {"access_token": "test-token", "content": [{"text": f'{secret} {{"password":"test-password"}}'}]}
        text = json.dumps(scrub(value, [secret]))
        for token in (secret, "test-token", "test-password"):
            self.assertNotIn(token, text)

    def test_pinned_release_digests(self):
        from build_download import ARTIFACTS, RELEASE
        self.assertEqual(RELEASE, "rust-v0.160.0")
        for _artifact, digest, _member in ARTIFACTS.values():
            self.assertRegex(digest, r"^[0-9a-f]{64}$")


class FakeResponse(io.BytesIO):
    def __init__(self, data, content_type):
        super().__init__(data)
        self.content_type = content_type

    def getheader(self, name, default=None):
        return self.content_type if name == "Content-Type" else default


class ProtocolTests(unittest.TestCase):
    def test_sse_response_id_and_multiline(self):
        response = FakeResponse(
            b'event: message\ndata: {"jsonrpc":"2.0",\ndata: "id":7,"result":{}}\n\n',
            "text/event-stream",
        )
        self.assertEqual(read_rpc_response(response, 7)["result"], {})

    def test_json_id_mismatch_denied(self):
        with self.assertRaises(PolicyError):
            read_rpc_response(FakeResponse(b'{"id":8,"result":{}}', "application/json"), 7)


class RelayTests(unittest.TestCase):
    def setUp(self):
        self.calls = []
        calls = self.calls

        class Upstream(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def do_POST(self):
                message = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                calls.append((self.path, message))
                result = {"tools": [{"name": "ha_search"}, {"name": "ha_set_entity"}]}
                payload = json.dumps({"jsonrpc": "2.0", "id": message["id"], "result": result}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.send_header("Mcp-Session-Id", "fake-session")
                self.end_headers()
                self.wfile.write(payload)

        self.upstream = ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
        url = f"http://127.0.0.1:{self.upstream.server_port}/private-secret-abcdefgh/mcp"
        self.relay = make_server(url, ("127.0.0.1", 0))
        for server in (self.upstream, self.relay):
            threading.Thread(target=server.serve_forever, daemon=True).start()

    def tearDown(self):
        for server in (self.relay, self.upstream):
            server.shutdown()
            server.server_close()

    def request(self, message):
        connection = http.client.HTTPConnection("127.0.0.1", self.relay.server_port)
        connection.request("POST", "/mcp", json.dumps(message), {"Content-Type": "application/json"})
        response = connection.getresponse()
        body = json.loads(response.read())
        status, session_id = response.status, response.getheader("Mcp-Session-Id")
        connection.close()
        return status, session_id, body

    def test_read_discovery_forwarded_and_filtered(self):
        status, session_id, body = self.request(rpc("tools/list"))
        self.assertEqual(status, 200)
        self.assertEqual(session_id, "fake-session")
        self.assertEqual(body["result"]["tools"], [{"name": "ha_search"}])
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(self.calls[0][0], "/private-secret-abcdefgh/mcp")

    def test_denied_call_never_reaches_upstream(self):
        status, _, body = self.request(rpc("tools/call", {"name": "ha_set_entity", "arguments": {}}))
        self.assertEqual(status, 403)
        self.assertEqual(self.calls, [])
        self.assertNotIn("private-secret", json.dumps(body))


if __name__ == "__main__":
    unittest.main()
