#!/usr/bin/env python3
"""Private Streamable HTTP MCP policy proxy and tunnel supervisor."""

from __future__ import annotations

import http.client
import json
import logging
import os
import signal
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlsplit


ALLOWED_TOOLS = frozenset(
    {
        "ha_config_get_automation",
        "ha_config_get_calendar_events",
        "ha_config_get_category",
        "ha_config_get_dashboard",
        "ha_config_get_label",
        "ha_config_get_scene",
        "ha_config_get_script",
        "ha_config_list_dashboard_resources",
        "ha_config_list_groups",
        "ha_config_list_helpers",
        "ha_eval_template",
        "ha_get_addon",
        "ha_get_automation_traces",
        "ha_get_blueprint",
        "ha_get_camera_image",
        "ha_get_device",
        "ha_get_entity",
        "ha_get_entity_exposure",
        "ha_get_hacs_info",
        "ha_get_history",
        "ha_get_integration",
        "ha_get_logs",
        "ha_get_operation_status",
        "ha_get_overview",
        "ha_get_skill_guide",
        "ha_get_state",
        "ha_get_system_health",
        "ha_get_todo",
        "ha_get_zone",
        "ha_list_floors_areas",
        "ha_list_services",
        "ha_search",
        "ha_bulk_control",
        "ha_call_service",
        "ha_config_set_automation",
        "ha_config_set_group",
        "ha_config_set_helper",
        "ha_config_set_scene",
        "ha_config_set_script",
        "ha_manage_backup",
        "ha_reload_core",
        "ha_set_area_or_floor",
        "ha_set_device",
        "ha_set_entity",
        "ha_set_integration",
    }
)

SAFE_RELOAD_TARGETS = frozenset(
    {
        "automations",
        "scripts",
        "scenes",
        "groups",
        "input_booleans",
        "input_numbers",
        "input_texts",
        "input_selects",
        "input_datetimes",
        "input_buttons",
        "timers",
        "templates",
        "persons",
        "zones",
        "themes",
    }
)

SAFE_SERVICES = {
    "light": {"turn_on", "turn_off", "toggle"},
    "switch": {"turn_on", "turn_off", "toggle"},
    "fan": {"turn_on", "turn_off", "toggle", "set_percentage", "set_preset_mode", "oscillate"},
    "cover": {"open_cover", "close_cover", "stop_cover", "set_cover_position", "open_cover_tilt", "close_cover_tilt", "stop_cover_tilt", "set_cover_tilt_position"},
    "climate": {"turn_on", "turn_off", "set_temperature", "set_hvac_mode", "set_fan_mode", "set_preset_mode", "set_humidity"},
    "humidifier": {"turn_on", "turn_off", "set_humidity", "set_mode"},
    "media_player": {"turn_on", "turn_off", "media_play", "media_pause", "media_stop", "media_next_track", "media_previous_track", "volume_set", "volume_up", "volume_down", "volume_mute", "select_source"},
    "vacuum": {"start", "pause", "stop", "return_to_base", "locate", "clean_spot", "clean_area"},
    "scene": {"turn_on"},
    "input_boolean": {"turn_on", "turn_off", "toggle"},
    "input_number": {"set_value", "increment", "decrement"},
    "input_select": {"select_option", "select_next", "select_previous", "select_first", "select_last"},
    "input_text": {"set_value"},
    "input_datetime": {"set_datetime"},
    "timer": {"start", "pause", "cancel", "finish", "change"},
    "select": {"select_option", "select_next", "select_previous", "select_first", "select_last"},
    "number": {"set_value"},
}

INFRASTRUCTURE_TERMS = frozenset(
    {
        "coordinator",
        "router",
        "hub",
        "bridge",
        "gateway",
        "matter_server",
        "mosquitto",
        "zigbee2mqtt",
        "home_assistant",
        "network",
        "deco",
        "d_link",
        "reset",
        "pair",
        "restart",
        "shutdown",
        "reboot",
        "delete",
        "remove",
        "factory",
        "calibrate",
        "calibration",
        "update",
    }
)

HOP_HEADERS = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
        "content-length",
        "host",
        "accept-encoding",
    }
)

POLICY_NOTE = (
    " Sunfish server policy: destructive deletion, removal, restore, restart, "
    "shutdown, pairing, reset and unrestricted service calls are blocked."
)


class BridgeState:
    def __init__(self, upstream_url: str) -> None:
        parsed = urlsplit(upstream_url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or not parsed.path:
            raise ValueError("upstream_url must be a complete private HTTP(S) MCP URL")
        self.upstream = parsed
        self.tunnel: subprocess.Popen[str] | None = None
        self.started = time.monotonic()


STATE: BridgeState


def safe_entity_target(value: Any) -> bool:
    if value is None:
        return True
    targets = value if isinstance(value, list) else [value]
    for target in targets:
        if not isinstance(target, str):
            return False
        lowered = target.lower()
        if any(term in lowered for term in INFRASTRUCTURE_TERMS):
            return False
    return True


def service_allowed(args: dict[str, Any]) -> tuple[bool, str]:
    if args.get("ws_command"):
        return False, "WebSocket command escape hatch is not exposed"
    domain = args.get("domain")
    service = args.get("service")
    if not isinstance(domain, str) or not isinstance(service, str):
        return False, "A named domain and service are required"
    if domain == "notify":
        if any(term in service.lower() for term in INFRASTRUCTURE_TERMS):
            return False, "Notification service name violates the protected-name policy"
    elif service not in SAFE_SERVICES.get(domain, set()):
        return False, "Service is outside the approved control policy"
    if not safe_entity_target(args.get("entity_id")):
        return False, "Infrastructure targets are protected"
    return True, ""


def configuration_actions_allowed(value: Any) -> tuple[bool, str]:
    """Reject opaque or unsafe actions embedded in automations and scripts."""
    if isinstance(value, list):
        for item in value:
            allowed, reason = configuration_actions_allowed(item)
            if not allowed:
                return allowed, reason
        return True, ""
    if not isinstance(value, dict):
        return True, ""
    if "device_id" in value:
        return False, "Opaque device actions are blocked; use approved entity service actions"
    for key in ("action", "service"):
        candidate = value.get(key)
        if candidate is None:
            continue
        if not isinstance(candidate, str) or "." not in candidate:
            return False, "Action must be a named approved domain.service"
        domain, service = candidate.split(".", 1)
        entity_id = value.get("target", {}).get("entity_id") if isinstance(value.get("target"), dict) else None
        if entity_id is None and isinstance(value.get("data"), dict):
            entity_id = value["data"].get("entity_id")
        allowed, reason = service_allowed({"domain": domain, "service": service, "entity_id": entity_id})
        if not allowed:
            return allowed, reason
    for nested in value.values():
        allowed, reason = configuration_actions_allowed(nested)
        if not allowed:
            return allowed, reason
    return True, ""


def tool_allowed(name: Any, args: Any) -> tuple[bool, str]:
    if not isinstance(name, str) or name not in ALLOWED_TOOLS:
        return False, "Tool is not exposed by the Sunfish profile"
    if not isinstance(args, dict):
        args = {}

    if name == "ha_manage_backup":
        if args.get("action") not in {"create", "list", "view", "diff"}:
            return False, "Backup restore and deletion are blocked"
    elif name == "ha_reload_core":
        if args.get("entry_id"):
            return False, "Integration-entry reload requires separate approval"
        if args.get("target", "all") not in SAFE_RELOAD_TARGETS:
            return False, "Broad, core and unsupported reload targets are blocked"
    elif name == "ha_set_integration":
        if args.get("domain") is not None or args.get("enabled") is not None:
            return False, "Only reversible options updates on existing integrations are allowed"
        if not args.get("entry_id") or not isinstance(args.get("config"), dict):
            return False, "Existing entry_id and options config are required"
    elif name == "ha_set_entity":
        if args.get("enabled") is not None:
            return False, "Registry enable/disable is blocked"
    elif name == "ha_set_device":
        if args.get("disabled_by") is not None:
            return False, "Device enable/disable is blocked"
    elif name in {"ha_config_set_automation", "ha_config_set_script"}:
        if args.get("python_transform") is not None:
            return False, "Python transforms are blocked on the ChatGPT path"
        if not isinstance(args.get("config"), dict):
            return False, "A complete configuration object is required"
        return configuration_actions_allowed(args["config"])
    elif name == "ha_config_set_scene":
        if args.get("python_transform") is not None:
            return False, "Python transforms are blocked on the ChatGPT path"
        config = args.get("config")
        if not isinstance(config, dict):
            return False, "A complete scene configuration object is required"
        entities = config.get("entities", {})
        if not isinstance(entities, dict) or not safe_entity_target(list(entities)):
            return False, "Scene contains a protected or invalid entity target"
    elif name == "ha_config_set_helper":
        if args.get("helper_type") == "config_subentry":
            return False, "Config-subentry creation is outside the helper policy"
    elif name == "ha_call_service":
        return service_allowed(args)
    elif name == "ha_bulk_control":
        operations = args.get("operations")
        if not isinstance(operations, list) or not operations or len(operations) > 25:
            return False, "Bulk control requires 1 to 25 operations"
        for operation in operations:
            if not isinstance(operation, dict):
                return False, "Every bulk operation must be an object"
            allowed, reason = service_allowed(operation)
            if not allowed:
                return False, reason
    return True, ""


def policy_error(request_id: Any, reason: str) -> bytes:
    return json.dumps(
        {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {"code": -32001, "message": f"Blocked by Sunfish MCP policy: {reason}"},
        },
        separators=(",", ":"),
    ).encode()


def inspect_request(body: bytes) -> tuple[bool, bytes | None, str | None]:
    try:
        payload = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return True, None, None
    requests = payload if isinstance(payload, list) else [payload]
    for request in requests:
        if not isinstance(request, dict) or request.get("method") != "tools/call":
            continue
        params = request.get("params") or {}
        allowed, reason = tool_allowed(params.get("name"), params.get("arguments"))
        if not allowed:
            logging.warning("policy_block tool=%s", params.get("name", "invalid"))
            return False, policy_error(request.get("id"), reason), reason
    return True, None, None


def narrow_schema(tool: dict[str, Any]) -> None:
    name = tool.get("name")
    tool["description"] = str(tool.get("description", "")) + POLICY_NOTE
    schema = tool.get("inputSchema")
    if not isinstance(schema, dict):
        return
    properties = schema.get("properties")
    if not isinstance(properties, dict):
        return
    if name == "ha_manage_backup" and isinstance(properties.get("action"), dict):
        properties["action"]["enum"] = ["create", "list", "view", "diff"]
    elif name == "ha_reload_core" and isinstance(properties.get("target"), dict):
        properties["target"]["enum"] = sorted(SAFE_RELOAD_TARGETS)
        properties.pop("entry_id", None)
    elif name == "ha_set_integration":
        properties.pop("domain", None)
        properties.pop("enabled", None)
    elif name == "ha_set_entity":
        properties.pop("enabled", None)
    elif name == "ha_set_device":
        properties.pop("disabled_by", None)
    elif name in {"ha_config_set_automation", "ha_config_set_script", "ha_config_set_scene"}:
        properties.pop("python_transform", None)


def filter_tool_result(value: Any) -> Any:
    containers = value if isinstance(value, list) else [value]
    for item in containers:
        if not isinstance(item, dict):
            continue
        result = item.get("result")
        if not isinstance(result, dict) or not isinstance(result.get("tools"), list):
            continue
        filtered = []
        for tool in result["tools"]:
            if isinstance(tool, dict) and tool.get("name") in ALLOWED_TOOLS:
                narrow_schema(tool)
                filtered.append(tool)
        result["tools"] = filtered
    return value


def filter_response(body: bytes, content_type: str) -> bytes:
    if "application/json" in content_type:
        try:
            value = json.loads(body)
            return json.dumps(filter_tool_result(value), separators=(",", ":")).encode()
        except (json.JSONDecodeError, UnicodeDecodeError):
            return body
    if "text/event-stream" in content_type:
        output: list[bytes] = []
        for line in body.splitlines(keepends=True):
            if line.startswith(b"data:"):
                prefix, data = line.split(b":", 1)
                ending = b"\n" if line.endswith(b"\n") else b""
                try:
                    value = json.loads(data.strip())
                    encoded = json.dumps(filter_tool_result(value), separators=(",", ":")).encode()
                    line = prefix + b": " + encoded + ending
                except (json.JSONDecodeError, UnicodeDecodeError):
                    pass
            output.append(line)
        return b"".join(output)
    return body


def read_request_body(handler: BaseHTTPRequestHandler) -> bytes:
    length = handler.headers.get("Content-Length")
    if length:
        return handler.rfile.read(int(length))
    return b""


class ProxyHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, _format: str, *args: Any) -> None:
        return

    def do_GET(self) -> None:
        self.forward()

    def do_POST(self) -> None:
        self.forward()

    def do_DELETE(self) -> None:
        self.forward()

    def forward(self) -> None:
        started = time.monotonic()
        body = read_request_body(self)
        if self.command == "POST":
            allowed, error, _ = inspect_request(body)
            if not allowed and error is not None:
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(error)))
                self.end_headers()
                self.wfile.write(error)
                return

        parsed = STATE.upstream
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        connection_type = http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
        connection = connection_type(parsed.hostname, port, timeout=180)
        headers = {k: v for k, v in self.headers.items() if k.lower() not in HOP_HEADERS}
        if body:
            headers["Content-Length"] = str(len(body))
        target = parsed.path
        if parsed.query:
            target += "?" + parsed.query
        try:
            connection.request(self.command, target, body=body or None, headers=headers)
            response = connection.getresponse()
            if self.command == "GET" and "text/event-stream" in response.getheader("Content-Type", ""):
                self.send_response(response.status)
                for key, value in response.getheaders():
                    if key.lower() not in HOP_HEADERS:
                        self.send_header(key, value)
                self.send_header("Connection", "close")
                self.end_headers()
                self.close_connection = True
                while True:
                    chunk = response.read(8192)
                    if not chunk:
                        break
                    self.wfile.write(chunk)
                    self.wfile.flush()
                return
            response_body = response.read(16 * 1024 * 1024 + 1)
            if len(response_body) > 16 * 1024 * 1024:
                raise ValueError("upstream response exceeded policy limit")
            content_type = response.getheader("Content-Type", "")
            response_body = filter_response(response_body, content_type)
            self.send_response(response.status)
            for key, value in response.getheaders():
                if key.lower() not in HOP_HEADERS:
                    self.send_header(key, value)
            self.send_header("Content-Length", str(len(response_body)))
            self.end_headers()
            if response_body:
                self.wfile.write(response_body)
            logging.info("mcp_forward method=%s status=%s duration_ms=%d", self.command, response.status, int((time.monotonic() - started) * 1000))
        except Exception as exc:
            logging.error("mcp_forward_failed error_type=%s", type(exc).__name__)
            payload = policy_error(None, "Private upstream temporarily unavailable")
            self.send_response(502)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
        finally:
            connection.close()


class HealthHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, _format: str, *args: Any) -> None:
        return

    def do_GET(self) -> None:
        if self.path not in {"/healthz", "/readyz"}:
            self.send_error(404)
            return
        process_ok = STATE.tunnel is not None and STATE.tunnel.poll() is None
        tunnel_path = "/readyz" if self.path == "/readyz" else "/healthz"
        tunnel_ok = False
        if process_ok:
            try:
                connection = http.client.HTTPConnection("127.0.0.1", 8080, timeout=2)
                connection.request("GET", tunnel_path)
                response = connection.getresponse()
                response.read()
                tunnel_ok = 200 <= response.status < 300
                connection.close()
            except Exception:
                tunnel_ok = False
        status = 200 if process_ok and tunnel_ok else 503
        payload = json.dumps({"status": "ok" if status == 200 else "unavailable"}).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


def serve(server: ThreadingHTTPServer) -> None:
    server.serve_forever(poll_interval=0.25)


def write_secret(path: str, value: str) -> None:
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as secret_file:
        secret_file.write(value)


def main() -> int:
    global STATE
    with open("/data/options.json", "r", encoding="utf-8") as options_file:
        options = json.load(options_file)
    tunnel_id = options.get("tunnel_id")
    runtime_api_key = options.get("runtime_api_key")
    upstream_url = options.get("upstream_url")
    log_level = str(options.get("log_level", "info")).lower()
    if not all(isinstance(value, str) and value.strip() for value in (tunnel_id, runtime_api_key, upstream_url)):
        raise ValueError("tunnel_id, runtime_api_key and upstream_url are required")

    logging.basicConfig(
        level=logging.WARNING if log_level == "warn" else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )
    STATE = BridgeState(upstream_url)
    secret_path = "/run/secrets/control-plane-api-key"
    write_secret(secret_path, runtime_api_key)

    proxy = ThreadingHTTPServer(("127.0.0.1", 8765), ProxyHandler)
    health = ThreadingHTTPServer(("0.0.0.0", 8790), HealthHandler)
    threading.Thread(target=serve, args=(proxy,), name="mcp-proxy", daemon=True).start()
    threading.Thread(target=serve, args=(health,), name="health", daemon=True).start()

    command = [
        "/usr/bin/tunnel-client",
        "run",
        f"--control-plane.tunnel-id={tunnel_id}",
        f"--control-plane.api-key=file:{secret_path}",
        "--mcp.server-url=http://127.0.0.1:8765/mcp",
        "--mcp.max-concurrent-requests=6",
        "--health.listen-addr=127.0.0.1:8080",
        f"--log.level={log_level}",
        "--log.format=json",
    ]
    STATE.tunnel = subprocess.Popen(command, text=True)
    logging.info("bridge_started allowed_tools=%d", len(ALLOWED_TOOLS))

    stopping = threading.Event()

    def stop(_signum: int, _frame: Any) -> None:
        stopping.set()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    while not stopping.wait(1):
        if STATE.tunnel.poll() is not None:
            logging.error("tunnel_client_exited")
            break

    proxy.shutdown()
    health.shutdown()
    if STATE.tunnel.poll() is None:
        STATE.tunnel.terminate()
        try:
            STATE.tunnel.wait(timeout=10)
        except subprocess.TimeoutExpired:
            STATE.tunnel.kill()
    try:
        os.remove(secret_path)
    except FileNotFoundError:
        pass
    return 0 if stopping.is_set() else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
        logging.error("bridge_start_failed error_type=%s", type(exc).__name__)
        sys.exit(1)
