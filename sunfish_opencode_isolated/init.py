"""Container initialization and supervision. No Supervisor or HA API calls."""

import json
import os
import pwd
import signal
import stat
import subprocess
import tempfile
import threading
import time
from pathlib import Path

from mcp_proxy import make_server
from readiness import (offline_probe_environment, run_check, run_config_readiness,
                       run_offline_catalog_readiness, run_readiness, unprivileged_command)
from runtime_config import (MANAGED_CONFIG_PATH, ROOT_DIRECTORIES,
                            USER_DIRECTORIES, build_environment, build_runtime_config)
from security import render_nginx_config, validate_user_id

def ensure_directory(filename, uid, gid, mode):
    path = Path(filename)
    if path.is_symlink():
        raise RuntimeError("Unexpected persistent directory symlink")
    path.mkdir(parents=True, exist_ok=True)
    if not path.is_dir():
        raise RuntimeError("Unexpected persistent directory type")
    os.chown(path, uid, gid)
    os.chmod(path, mode)


def protected_write(filename, content, mode=0o644):
    descriptor = os.open(filename, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, mode)
    with os.fdopen(descriptor, "w") as handle:
        handle.write(content)
    os.chown(filename, 0, 0)
    os.chmod(filename, mode)


def validate_native_configuration(enable_mcp, user):
    """No auth, prompts, HA requests, or model inference in readiness checks.

    Start with no MCP entry at all; only enable the fixed loopback configuration
    after the embedded catalog and deny-all policy pass. Even its final native
    config check precedes relay creation, so no private HA endpoint is available.
    A failure leaves the app stopped, never falling back to an unrestricted CLI.
    """
    offline = build_runtime_config(enable_mcp=False)
    protected_write(MANAGED_CONFIG_PATH, json.dumps(offline, indent=2) + "\n")
    # Fresh /run storage prevents saved auth/accounts/models from influencing
    # the embedded-catalog proof. The temporary parent stays root-owned.
    with tempfile.TemporaryDirectory(prefix="sunfish-opencode-readiness-", dir="/run") as temporary:
        ensure_directory(temporary, 0, 0, 0o755)
        for suffix in ("data", "cache", "state", "tmp"):
            ensure_directory(str(Path(temporary) / suffix), user.pw_uid, user.pw_gid, 0o700)
        environment = offline_probe_environment(temporary)
        run_offline_catalog_readiness(environment)
        config = build_runtime_config(enable_mcp=enable_mcp)
        protected_write(MANAGED_CONFIG_PATH, json.dumps(config, indent=2) + "\n")
        run_config_readiness(environment, enable_mcp=enable_mcp)


def main():
    os.umask(0o077)
    # Remove inherited platform tokens from parent as well as child environments.
    os.environ.clear()
    options_path = Path("/data/options.json")
    if options_path.is_symlink() or not stat.S_ISREG(options_path.stat().st_mode):
        raise RuntimeError("Unexpected options type")
    os.chown(options_path, 0, 0)
    os.chmod(options_path, 0o600)
    options = json.loads(options_path.read_text())
    allowed_user_id = validate_user_id(options.get("allowed_user_id"))
    user = pwd.getpwnam("opencode")
    if user.pw_uid != 1000 or user.pw_gid != 1000:
        raise RuntimeError("Unexpected coding user identity")
    for directory in ROOT_DIRECTORIES:
        ensure_directory(directory, 0, 0, 0o755)
    # Parent paths are checked first; UID 1000 cannot substitute a symlink that
    # would make a subsequent root chown/chmod follow it outside the workspace.
    persistent_parents = ("/data/opencode", "/data/opencode/data", "/data/opencode/cache",
                          "/data/opencode/state")
    for directory in dict.fromkeys((*persistent_parents, *USER_DIRECTORIES)):
        ensure_directory(directory, user.pw_uid, user.pw_gid, 0o700)
    # Traverse only: the root-owned credential file cannot be listed/read.
    os.chmod("/data", 0o711)
    # Boundary probes require the managed file to exist before native probes.
    config = build_runtime_config(enable_mcp=False)
    protected_write(MANAGED_CONFIG_PATH, json.dumps(config, indent=2) + "\n")
    ensure_directory("/run/nginx", 0, 0, 0o755)
    nginx_config = render_nginx_config(Path("/etc/nginx/nginx.conf").read_text(), allowed_user_id)
    nginx_path = "/run/sunfish-nginx.conf"
    protected_write(nginx_path, nginx_config, 0o600)
    environment = build_environment()
    run_check("ingress configuration", ["/usr/sbin/nginx", "-t", "-c", nginx_path], environment)
    run_readiness(environment)
    validate_native_configuration(enable_mcp=bool(options.get("mcp_url")), user=user)
    print("Readiness ingress owner-ID gate: configured (identity not logged)", flush=True)
    print("Readiness isolation: outer container only; no Codex/bwrap sandbox claimed", flush=True)
    relay = None
    if options.get("mcp_url"):
        relay = make_server(options["mcp_url"])
        threading.Thread(target=relay.serve_forever, daemon=True).start()
        print("Readiness HA MCP policy: fixed ten-tool read-only relay enabled", flush=True)
    else:
        print("Readiness HA MCP policy: not configured; no HA access", flush=True)
    children = []
    stopping = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_args: stopping.set())
    try:
        children.append(subprocess.Popen(["/usr/sbin/nginx", "-c", nginx_path,
                                          "-g", "daemon off;"], env=environment))
        children.append(subprocess.Popen(
            unprivileged_command("/usr/bin/ttyd", "--interface", "127.0.0.1",
                                 "--port", "7681", "--writable", "--max-clients", "1",
                                 "--check-origin", "/usr/local/bin/opencode-session"), env=environment))
        print("OpenCode terminal ready; cloud requests start only after user prompts", flush=True)
        while not stopping.wait(1):
            if any(child.poll() is not None for child in children):
                raise RuntimeError("App child exited")
    finally:
        if relay:
            relay.shutdown()
            relay.server_close()
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
        # No traceback/exception text can reveal the private MCP endpoint.
        print("Isolated OpenCode startup failed; inspect fixed readiness categories. "
              "Do not share credentials or relax isolation.", flush=True)
        raise SystemExit(1)
