"""Read-only MCP relay. The secret upstream URL stays in the root process.

No mixed read/write tools are exposed. An OpenCode config edit cannot lift this
allowlist. Only the standard library is required; no third-party Python wheels.
"""

import http.client
import json
import re
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

ALLOWED_TOOLS = frozenset({
    "ha_search", "ha_get_state", "ha_get_history", "ha_get_entity",
    "ha_get_device", "ha_get_entity_exposure", "ha_get_overview",
    "ha_config_get_label", "ha_get_zone", "ha_get_skill_guide",
})
MAX_REQUEST = 1024 * 1024
MAX_RESPONSE = 32 * 1024 * 1024
MAX_CONCURRENT_REQUESTS = 8
REQUEST_DEADLINE_SECONDS = 120
SKILL_URI = re.compile(
    r"^skill://home-assistant-best-practices/(?:SKILL\.md|references/[A-Za-z0-9_-]+\.md)$"
)
SENSITIVE_KEYS = frozenset({
    "access_token", "refresh_token", "api_key", "password", "secret", "token",
    "authorization", "mqtt_password", "network_key", "install_code",
})
SENSITIVE_TEXT_PAIR = re.compile(
    r'("(?:' + "|".join(re.escape(key) for key in sorted(SENSITIVE_KEYS)) +
    r')"\s*:\s*)"(?:\\.|[^"\\\r\n])*"', re.IGNORECASE,
)


class PolicyError(ValueError):
    pass


def close_socket(connection):
    """Shutdown interrupts makefile reads even when a peer keeps trickling data."""
    try:
        connection.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    try:
        connection.close()
    except OSError:
        pass


class RequestDeadline:
    """One absolute budget covers headers, body, upstream and response delivery.

    A socket timeout alone restarts on every successful read. The independent
    timer closes both sockets at the deadline, including during buffered reads.
    """

    def __init__(self, seconds):
        self.expires_at = time.monotonic() + seconds
        self.lock = threading.Lock()
        self.sockets = set()
        self.expired = False
        self.finished = False
        self.timer = threading.Timer(seconds, self._expire)
        self.timer.daemon = True
        self.timer.start()

    def _expire(self):
        with self.lock:
            if self.finished:
                return
            self.expired = True
            connections = list(self.sockets)
        for connection in connections:
            close_socket(connection)

    def check(self):
        if self.expired or time.monotonic() >= self.expires_at:
            self._expire()
            raise TimeoutError("MCP request deadline elapsed")

    def remaining(self):
        self.check()
        return max(0.001, self.expires_at - time.monotonic())

    def attach_socket(self, connection):
        with self.lock:
            expired = self.expired
            if not expired:
                self.sockets.add(connection)
        if expired:
            close_socket(connection)
        self.check()

    def cancel(self):
        with self.lock:
            self.finished = True
            self.sockets.clear()
        self.timer.cancel()


class BoundedThreadingHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    block_on_close = False

    def __init__(self, *args, **kwargs):
        self.request_slots = threading.BoundedSemaphore(MAX_CONCURRENT_REQUESTS)
        super().__init__(*args, **kwargs)

    def process_request(self, request, client_address):
        if not self.request_slots.acquire(blocking=False):
            # No body is read and no upstream request is sent when at capacity.
            try:
                request.settimeout(1)
                request.sendall(b"HTTP/1.1 503 Service Unavailable\r\n"
                                b"Connection: close\r\nContent-Length: 0\r\n\r\n")
            except OSError:
                pass
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.request_slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.request_slots.release()

    def handle_error(self, _request, _client_address):
        # The base server prints tracebacks. Never disclose endpoint/body data.
        pass


def check_request(message):
    if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
        raise PolicyError("Single JSON-RPC 2.0 request required")
    method = message.get("method")
    params = message.get("params", {})
    if not isinstance(params, dict):
        raise PolicyError("Object parameters required")
    if method == "tools/call":
        if params.get("name") not in ALLOWED_TOOLS:
            raise PolicyError("Tool is not on the read-only allowlist")
        if not isinstance(params.get("arguments", {}), dict):
            raise PolicyError("Object tool arguments required")
        if params["name"] == "ha_get_skill_guide":
            file = params.get("arguments", {}).get("file")
            if file is not None and (not isinstance(file, str) or not re.fullmatch(
                r"references/[A-Za-z0-9_-]+\.md", file
            )):
                raise PolicyError("Only skill reference documents are readable")
    elif method == "resources/read":
        if not isinstance(params.get("uri"), str) or not SKILL_URI.fullmatch(params["uri"]):
            raise PolicyError("Only HA best-practice skill documents are readable")
    elif method not in {
        "initialize", "notifications/initialized", "notifications/cancelled",
        "ping", "tools/list", "resources/list", "resources/templates/list", "prompts/list",
    }:
        raise PolicyError("MCP method is not permitted")
    if "id" not in message and method not in {"notifications/initialized", "notifications/cancelled"}:
        raise PolicyError("Request ID required")
    return method


def filter_response(message, method):
    if not isinstance(message, dict):
        raise PolicyError("Invalid upstream response")
    result = message.get("result")
    if isinstance(result, dict) and method == "tools/list":
        result["tools"] = [t for t in result.get("tools", [])
                           if isinstance(t, dict) and t.get("name") in ALLOWED_TOOLS]
    if isinstance(result, dict) and method == "resources/list":
        result["resources"] = [r for r in result.get("resources", [])
                               if isinstance(r, dict) and isinstance(r.get("uri"), str)
                               and SKILL_URI.fullmatch(r["uri"])]
    return message


def scrub(value, replacements):
    if isinstance(value, dict):
        return {k: "[redacted]" if k.lower() in SENSITIVE_KEYS else scrub(v, replacements)
                for k, v in value.items()}
    if isinstance(value, list):
        return [scrub(v, replacements) for v in value]
    if isinstance(value, str):
        for item in replacements:
            if item:
                value = value.replace(item, "[redacted MCP endpoint]")
        # MCP text blocks commonly duplicate a whole structured JSON result.
        # Parse those recursively, including array/numeric secret values and
        # JSON strings nested inside JSON, then use the same key set for snippets.
        try:
            embedded = json.loads(value)
        except (ValueError, RecursionError):
            embedded = None
        if isinstance(embedded, (dict, list)):
            return json.dumps(scrub(embedded, replacements))
        value = SENSITIVE_TEXT_PAIR.sub(r'\1"[redacted]"', value)
    return value


def read_rpc_response(response, request_id, deadline=None):
    if deadline:
        deadline.check()
    content_type = response.getheader("Content-Type", "").split(";", 1)[0].strip()
    if content_type == "application/json":
        data = response.read(MAX_RESPONSE + 1)
        if deadline:
            deadline.check()
        if len(data) > MAX_RESPONSE:
            raise PolicyError("Upstream response exceeds size limit")
        message = json.loads(data)
        if not isinstance(message, dict) or message.get("id") != request_id:
            raise PolicyError("Upstream response ID mismatch")
        return message
    if content_type != "text/event-stream":
        raise PolicyError("Unsupported upstream content type")
    total, data_lines = 0, []
    while True:
        if deadline:
            deadline.check()
        line = response.readline(MAX_RESPONSE + 1)
        if deadline:
            deadline.check()
        total += len(line)
        if total > MAX_RESPONSE:
            raise PolicyError("Upstream event stream exceeds size limit")
        if not line:
            raise PolicyError("Upstream event stream ended without a response")
        line = line.rstrip(b"\r\n")
        if line.startswith(b"data:"):
            data_lines.append(line[5:].lstrip(b" "))
        elif not line and data_lines:
            message = json.loads(b"\n".join(data_lines))
            data_lines.clear()
            if isinstance(message, dict) and message.get("id") == request_id:
                return message


def make_server(upstream_url, address=("127.0.0.1", 8091)):
    parsed = urlsplit(upstream_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.fragment:
        raise PolicyError("MCP URL must be an HTTP(S) endpoint without userinfo or fragment")
    upstream_path = parsed.path or "/"
    if parsed.query:
        upstream_path += "?" + parsed.query
    replacements = sorted({upstream_url, parsed.netloc,
                           upstream_path if len(upstream_path) > 8 else ""}, key=len, reverse=True)

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def handle_one_request(self):
            # Start before the request line/headers, not after body parsing.
            self.request_deadline = RequestDeadline(REQUEST_DEADLINE_SECONDS)
            try:
                self.request_deadline.attach_socket(self.connection)
                self.connection.settimeout(self.request_deadline.remaining())
                super().handle_one_request()
            except OSError:
                self.close_connection = True
            finally:
                if self.request_deadline.expired:
                    self.close_connection = True
                self.request_deadline.cancel()

        def log_message(self, *_args):
            # Never log request bodies, paths, upstream endpoints, or credentials.
            pass

        def reply(self, status, message=None, session_id=None):
            body = b"" if message is None else json.dumps(message).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            if session_id:
                self.send_header("Mcp-Session-Id", session_id)
            self.end_headers()
            if body:
                self.wfile.write(body)

        def do_GET(self):
            # Streamable HTTP permits a server without a persistent GET stream.
            self.reply(405)

        def do_POST(self):
            request_id = None
            connection = None
            try:
                if self.path != "/mcp" or self.headers.get("Transfer-Encoding"):
                    raise PolicyError("Unsupported request framing or path")
                size = int(self.headers.get("Content-Length", "0"))
                if not 0 < size <= MAX_REQUEST:
                    raise PolicyError("Request exceeds size limit")
                message = json.loads(self.rfile.read(size))
                self.request_deadline.check()
                request_id = message.get("id") if isinstance(message, dict) else None
                method = check_request(message)
                if method in {"ping", "prompts/list", "resources/templates/list"}:
                    key = {"prompts/list": "prompts", "resources/templates/list": "resourceTemplates"}.get(method)
                    self.reply(200, {"jsonrpc": "2.0", "id": request_id,
                                     "result": {key: []} if key else {}})
                    return
                headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
                for name in ("Mcp-Session-Id", "MCP-Protocol-Version"):
                    if self.headers.get(name):
                        headers[name] = self.headers[name]
                cls = http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
                connection = cls(parsed.hostname, parsed.port,
                                 timeout=self.request_deadline.remaining())
                # Connect explicitly, then never reconnect if the timer closes
                # the socket. A DNS/connect completion after expiry sends no RPC.
                connection.connect()
                self.request_deadline.attach_socket(connection.sock)
                connection.auto_open = 0
                self.request_deadline.check()
                connection.request("POST", upstream_path, json.dumps(message).encode(), headers)
                response = connection.getresponse()
                if "id" not in message and response.status in {200, 202, 204}:
                    self.reply(202)
                    return
                if response.status != 200:
                    raise PolicyError("Upstream MCP request did not succeed")
                result = filter_response(read_rpc_response(response, request_id, self.request_deadline), method)
                self.request_deadline.check()
                self.reply(200, scrub(result, replacements), response.getheader("Mcp-Session-Id"))
            except PolicyError:
                self.error_reply(403, request_id, -32600,
                                 "Read-only MCP policy denied or invalid response")
            except Exception:
                self.error_reply(502, request_id, -32603, "MCP relay unavailable")
            finally:
                if connection:
                    connection.close()

        def error_reply(self, status, request_id, code, message):
            self.close_connection = True
            try:
                self.reply(status, {"jsonrpc": "2.0", "id": request_id,
                                    "error": {"code": code, "message": message}})
            except OSError:
                # A deadline may already have closed the inbound connection.
                pass

    return BoundedThreadingHTTPServer(address, Handler)
