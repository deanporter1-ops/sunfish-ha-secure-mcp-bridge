"""Offline relay hardening tests. Fake local endpoints and fake secrets only."""

import contextlib
import http.client
import io
import json
import socket
import sys
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parents[1]))
import mcp_proxy


def rpc():
    return {"jsonrpc": "2.0", "id": 7, "method": "tools/call",
            "params": {"name": "ha_get_state", "arguments": {"entity_id": "sensor.fake"}}}


@contextlib.contextmanager
def running_relay(mode="fast", deadline=0.35, slots=2):
    requests = []
    connected = threading.Event()

    class FakeHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_args):
            pass

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            requests.append(body)
            connected.set()
            if mode == "error":
                self.send_response(500)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            self.send_response(200)
            if mode in {"sse", "json_trickle"}:
                self.send_header("Content-Type", "text/event-stream" if mode == "sse" else "application/json")
                self.send_header("Connection", "close")
                self.end_headers()
                self.close_connection = True
                try:
                    # Every read succeeds faster than the socket timeout, but
                    # the complete stream exceeds the absolute deadline.
                    for _ in range(40):
                        self.wfile.write(b":keepalive\n\n" if mode == "sse" else b" ")
                        self.wfile.flush()
                        time.sleep(0.03)
                except OSError:
                    pass
                return
            text = json.dumps({"mqtt_password": "FAKE_MQTT_SECRET", "install_code": "FAKE_INSTALL_SECRET"})
            payload = json.dumps({"jsonrpc": "2.0", "id": body["id"],
                                  "result": {"content": [{"type": "text", "text": text}]}}).encode()
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

    class FakeServer(ThreadingHTTPServer):
        daemon_threads = True
        block_on_close = False

        def handle_error(self, *_args):
            pass

    upstream = FakeServer(("127.0.0.1", 0), FakeHandler)
    with patch.object(mcp_proxy, "REQUEST_DEADLINE_SECONDS", deadline), \
            patch.object(mcp_proxy, "MAX_CONCURRENT_REQUESTS", slots):
        relay = mcp_proxy.make_server(f"http://127.0.0.1:{upstream.server_port}/fake-private-mcp-path", ("127.0.0.1", 0))
        threads = [threading.Thread(target=server.serve_forever, daemon=True) for server in (upstream, relay)]
        for thread in threads:
            thread.start()
        try:
            yield relay.server_port, requests, connected
        finally:
            relay.shutdown()
            relay.server_close()
            upstream.shutdown()
            upstream.server_close()
            for thread in threads:
                thread.join(timeout=2)


class RedactionTests(unittest.TestCase):
    def test_all_sensitive_keys_redact_both_structured_and_json_text(self):
        for key in mcp_proxy.SENSITIVE_KEYS:
            with self.subTest(key=key):
                value = {key: "FAKE_SECRET"}
                self.assertEqual(mcp_proxy.scrub(value, []), {key: "[redacted]"})
                self.assertEqual(json.loads(mcp_proxy.scrub(json.dumps(value), [])), {key: "[redacted]"})
                snippet = f'prefix {{"{key}": "FAKE_SECRET"}} suffix'
                self.assertNotIn("FAKE_SECRET", mcp_proxy.scrub(snippet, []))

    def test_nested_json_escaped_values_numeric_and_array_secrets(self):
        values = {"mqtt_password": 'FAKE_"ESCAPED_SECRET', "install_code": 123456,
                  "network_key": [1, 2, 3], "nested": json.dumps({"INSTALL_CODE": "FAKE_NESTED"})}
        result = json.loads(mcp_proxy.scrub(json.dumps(values), []))
        self.assertEqual(result["mqtt_password"], "[redacted]")
        self.assertEqual(result["install_code"], "[redacted]")
        self.assertEqual(result["network_key"], "[redacted]")
        self.assertEqual(json.loads(result["nested"])["INSTALL_CODE"], "[redacted]")


class DeadlineTests(unittest.TestCase):
    def call(self, port):
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
        try:
            connection.request("POST", "/mcp", json.dumps(rpc()), {"Content-Type": "application/json"})
            response = connection.getresponse()
            return response.status, response.read()
        finally:
            connection.close()

    def test_success_and_text_redaction_still_work(self):
        with running_relay(deadline=2) as (port, requests, _connected):
            status, payload = self.call(port)
            self.assertEqual(status, 200)
            self.assertNotIn(b"FAKE_MQTT_SECRET", payload)
            self.assertNotIn(b"FAKE_INSTALL_SECRET", payload)
            self.assertEqual(len(requests), 1)
            self.assertEqual(len(mcp_proxy.ALLOWED_TOOLS), 10)

    def test_upstream_sse_keepalives_and_json_trickles_stop_at_absolute_deadline(self):
        for mode in ("sse", "json_trickle"):
            with self.subTest(mode=mode), running_relay(mode) as (port, requests, _connected):
                start = time.monotonic()
                with self.assertRaises((OSError, http.client.RemoteDisconnected)):
                    self.call(port)
                self.assertLess(time.monotonic() - start, 1.2)
                # A timeout closes the existing socket; it never retries the RPC.
                time.sleep(0.1)
                self.assertEqual(len(requests), 1)

    def test_inbound_body_trickle_times_out_without_upstream_call(self):
        with running_relay() as (port, requests, _connected):
            connection = socket.create_connection(("127.0.0.1", port), timeout=2)
            connection.settimeout(2)
            body = json.dumps(rpc()).encode()
            start = time.monotonic()
            try:
                connection.sendall(f"POST /mcp HTTP/1.1\r\nHost: localhost\r\nContent-Length: {len(body)}\r\n\r\n".encode())
                for byte in body[:15]:
                    try:
                        connection.sendall(bytes([byte]))
                    except OSError:
                        break
                    time.sleep(0.03)
                try:
                    reply = connection.recv(1024)
                except OSError:
                    reply = b""
                self.assertEqual(reply, b"")
                self.assertLess(time.monotonic() - start, 1.2)
                self.assertEqual(requests, [])
            finally:
                connection.close()

    def test_inbound_header_trickle_also_has_an_absolute_deadline(self):
        with running_relay() as (port, requests, _connected):
            connection = socket.create_connection(("127.0.0.1", port), timeout=2)
            connection.settimeout(2)
            start = time.monotonic()
            try:
                connection.sendall(b"POST /mcp HTTP/1.1\r\nX-Trickle: ")
                for _ in range(15):
                    try:
                        connection.sendall(b"a")
                    except OSError:
                        break
                    time.sleep(0.03)
                try:
                    reply = connection.recv(1024)
                except OSError:
                    reply = b""
                self.assertEqual(reply, b"")
                self.assertLess(time.monotonic() - start, 1.2)
                self.assertEqual(requests, [])
            finally:
                connection.close()

    def test_concurrency_is_capped_before_forwarding_and_slots_recover(self):
        with running_relay(deadline=0.6, slots=1) as (port, requests, _connected):
            held = socket.create_connection(("127.0.0.1", port), timeout=2)
            held.sendall(b"POST /mcp HTTP/1.1\r\nHost: localhost\r\nContent-Length: 100\r\n\r\n{")
            try:
                time.sleep(0.1)
                rejected_at = time.monotonic()
                try:
                    status, _body = self.call(port)
                except OSError:
                    # Closing a connection with an unread body may produce a
                    # reset/abort before the best-effort 503 can be delivered.
                    status = None
                self.assertIn(status, (None, 503))
                self.assertLess(time.monotonic() - rejected_at, 0.5)
                self.assertEqual(requests, [])
                time.sleep(0.7)
                status, _body = self.call(port)
                self.assertEqual(status, 200)
                self.assertEqual(len(requests), 1)
            finally:
                held.close()

    def test_late_upstream_connect_sends_no_rpc_after_deadline(self):
        with running_relay() as (port, requests, _connected):
            original_connect = http.client.HTTPConnection.connect

            def slow_upstream_connect(connection):
                if connection.port != port:
                    time.sleep(0.5)
                original_connect(connection)

            start = time.monotonic()
            with patch.object(http.client.HTTPConnection, "connect", slow_upstream_connect):
                with self.assertRaises(OSError):
                    self.call(port)
                self.assertLess(time.monotonic() - start, 1.2)
                time.sleep(0.3)
                self.assertEqual(requests, [])

    def test_upstream_failure_has_no_secret_response_or_exception_log(self):
        output = io.StringIO()
        with contextlib.redirect_stderr(output), running_relay("error", deadline=2) as (port, requests, _connected):
            status, body = self.call(port)
            self.assertEqual(status, 403)
            self.assertEqual(json.loads(body)["error"]["message"], "Read-only MCP policy denied or invalid response")
            self.assertNotIn(b"fake-private-mcp-path", body)
            self.assertEqual(len(requests), 1)
        self.assertEqual(output.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
