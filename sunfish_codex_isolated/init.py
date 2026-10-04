"""Container-only initialization and child supervision. No Supervisor/API calls."""

import json
import os
import pwd
import signal
import subprocess
import threading
import time
from pathlib import Path

from mcp_proxy import ALLOWED_TOOLS, make_server
from readiness import run_check, run_readiness
from security import render_nginx_config, validate_user_id


def main():
    os.umask(0o077)
    options_path = Path("/data/options.json")
    if options_path.is_symlink():
        raise RuntimeError("Unexpected options symlink")
    os.chown(options_path, 0, 0)
    os.chmod(options_path, 0o600)
    options = json.loads(options_path.read_text())
    allowed_user_id = validate_user_id(options.get("allowed_user_id"))
    user = pwd.getpwnam("codex")
    for directory in ("/data/home", "/data/home/.codex", "/data/workspace"):
        if Path(directory).is_symlink():
            raise RuntimeError("Unexpected persistent directory symlink")
        Path(directory).mkdir(parents=True, exist_ok=True)
        os.chown(directory, user.pw_uid, user.pw_gid)
        os.chmod(directory, 0o700)
    # Permit traverse, not listing, of the app's own /data parent.
    os.chmod("/data", 0o711)
    config = 'forced_login_method = "chatgpt"\ncli_auth_credentials_store = "file"\n'
    if options.get("mcp_url"):
        config += '\n[mcp_servers.sunfish_readonly]\nurl = "http://127.0.0.1:8091/mcp"\n'
        config += 'default_tools_approval_mode = "prompt"\n'
        config += "enabled_tools = " + json.dumps(sorted(ALLOWED_TOOLS)) + "\n"
    config_path = Path("/data/home/.codex/config.toml")
    descriptor = os.open(config_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "w") as handle:
        handle.write(config)
    os.chown(config_path, user.pw_uid, user.pw_gid)
    os.chmod(config_path, 0o600)
    Path("/run/nginx").mkdir(exist_ok=True)
    readiness_home = Path("/run/codex-readiness")
    readiness_home.mkdir(mode=0o700, exist_ok=True)
    os.chown(readiness_home, user.pw_uid, user.pw_gid)
    os.chmod(readiness_home, 0o700)
    nginx_config = render_nginx_config(Path("/etc/nginx/nginx.conf").read_text(), allowed_user_id)
    nginx_path = Path("/run/sunfish-nginx.conf")
    nginx_path.write_text(nginx_config)
    os.chmod(nginx_path, 0o600)
    environment = {
        "PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": "/data/home",
        "CODEX_HOME": "/data/home/.codex", "USER": "codex", "LOGNAME": "codex",
        "TERM": "xterm-256color", "LANG": "C.UTF-8", "HISTFILE": "/dev/null",
    }
    run_check("ingress configuration", ["/usr/sbin/nginx", "-t", "-c", str(nginx_path)], environment)
    run_readiness(environment)
    print("Readiness ingress owner-ID gate: configured (identity not logged)", flush=True)
    relay = None
    if options.get("mcp_url"):
        relay = make_server(options["mcp_url"])
        threading.Thread(target=relay.serve_forever, daemon=True).start()
    children = [
        subprocess.Popen(["/usr/sbin/nginx", "-c", str(nginx_path), "-g", "daemon off;"]),
        subprocess.Popen(["/sbin/su-exec", "codex:codex", "/usr/bin/ttyd", "--interface", "127.0.0.1",
                          "--port", "7681", "--writable", "--max-clients", "1",
                          "--check-origin", "/usr/local/bin/codex-session"], env=environment),
    ]
    stopping = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_args: stopping.set())
    try:
        while not stopping.wait(1):
            if any(child.poll() is not None for child in children):
                raise RuntimeError("App child exited; stopping isolated Codex")
    finally:
        if relay:
            relay.shutdown()
        for child in children:
            if child.poll() is None:
                child.terminate()
        deadline = time.monotonic() + 5
        for child in children:
            try:
                child.wait(timeout=max(0.1, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                child.kill()


if __name__ == "__main__":
    try:
        main()
    except Exception:
        # No traceback may expose a configured private MCP endpoint.
        print("Isolated Codex startup failed; inspect candidate compatibility without sharing credentials.", flush=True)
        raise SystemExit(1)
