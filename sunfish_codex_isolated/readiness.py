"""Credential-free startup probes; no HA calls, authentication, or secret output."""

import os
import subprocess
import sys
from pathlib import Path

VERSION = "codex-cli 0.160.0"
FORBIDDEN_MOUNTS = {
    "/config", "/homeassistant", "/addons", "/share", "/ssl", "/media",
    "/backup", "/backups", "/run/docker.sock", "/var/run/docker.sock",
    "/app_configs", "/addon_configs", "/local_apps", "/run/dbus",
}


class ReadinessError(RuntimeError):
    pass


def mount_boundary_ok(text):
    """Reject unexpected HA/host mounts, without printing host mount sources."""
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 6:
            return False
        mountpoint = fields[4].replace("\\040", " ")
        if any(mountpoint == path or mountpoint.startswith(path + "/")
               for path in FORBIDDEN_MOUNTS):
            return False
    return True


def namespace_identity_ok(identity, mapping):
    """Allow namespace-local root only if it maps solely to container UID 1000."""
    try:
        rows = [[int(value) for value in line.split()] for line in mapping.splitlines()]
    except ValueError:
        return False
    return rows == [[identity, 1000, 1]]


def probe(sandbox=False):
    if sandbox:
        for identity, filename in ((os.getuid(), "uid_map"), (os.getgid(), "gid_map")):
            if not namespace_identity_ok(identity, Path("/proc/self/" + filename).read_text()):
                return False
    elif os.getuid() != 1000 or os.getgid() != 1000:
        return False
    if not mount_boundary_ok(Path("/proc/self/mountinfo").read_text()):
        return False
    # Opening, not merely checking mode bits, verifies the effective UID boundary.
    try:
        descriptor = os.open("/data/options.json", os.O_RDONLY | os.O_NOFOLLOW)
    except PermissionError:
        pass
    except FileNotFoundError:
        # The outer non-sandboxed probe must already prove permission denial;
        # a sandbox may instead hide the path entirely, which is also safe.
        if not sandbox:
            return False
    else:
        os.close(descriptor)
        return False
    # A stock image may contain empty /media or /config directories; only a
    # mounted HA/host path is forbidden. The mountinfo check above is decisive.
    return True


def sandbox_command():
    # 0.160.0 uses the host-native `codex sandbox`, not `sandbox linux`.
    return ["su-exec", "codex:codex", "/usr/local/bin/codex", "sandbox",
            "--config", 'sandbox_mode="workspace-write"', "--",
            "/usr/bin/python3", "/opt/sunfish/readiness.py", "--sandbox-probe"]


def userns_command():
    return ["su-exec", "codex:codex", "/usr/local/bin/bwrap",
            "--unshare-user", "--uid", "1000", "--gid", "1000",
            "--ro-bind", "/", "/", "--proc", "/proc", "--dev", "/dev",
            "--die-with-parent", "--", "/bin/true"]


def run_check(label, command, environment, runner=subprocess.run, version=False):
    result = None
    try:
        result = runner(command, env=environment, cwd="/data/workspace",
                        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE, timeout=20, check=False)
        ok = result.returncode == 0
        if version:
            ok = ok and result.stdout.decode("utf-8", "replace").strip() == VERSION
    except (OSError, subprocess.TimeoutExpired):
        ok = False
    # Fixed labels only: never echo stderr, commands, config, URLs, or user IDs.
    print("Readiness " + label + (": PASS" if ok else ": FAIL"), flush=True)
    if not ok:
        # Emit only fixed diagnostic categories, never raw process output.
        raw_error = getattr(result, "stderr", b"") or b""
        if b"Operation not permitted" in raw_error:
            print("Readiness failure category: OPERATION_NOT_PERMITTED", flush=True)
        elif b"Permission denied" in raw_error:
            print("Readiness failure category: PERMISSION_DENIED", flush=True)
        elif b"unrecognized" in raw_error or b"unexpected argument" in raw_error:
            print("Readiness failure category: CLI_ARGUMENT_REJECTED", flush=True)
        raise ReadinessError("Isolated Codex compatibility check failed")


def run_readiness(environment):
    clean = dict(environment)
    # A separate empty home prevents the probe using persisted ChatGPT auth or MCP.
    clean["CODEX_HOME"] = "/run/codex-readiness"
    run_check("pinned Codex version", ["su-exec", "codex:codex",
              "/usr/local/bin/codex", "--version"], clean, version=True)
    run_check("UID and no-HA-mount boundary", ["su-exec", "codex:codex",
              "/usr/bin/python3", "/opt/sunfish/readiness.py", "--probe"], clean)
    run_check("unprivileged bwrap user namespace", userns_command(), clean)
    run_check("Codex workspace sandbox", sandbox_command(), clean)


if __name__ == "__main__":
    if sys.argv[1:] not in (["--probe"], ["--sandbox-probe"]):
        raise SystemExit(2)
    try:
        raise SystemExit(0 if probe(sandbox=sys.argv[1] == "--sandbox-probe") else 1)
    except Exception:
        raise SystemExit(1)
