"""Credential-free outer-container checks; no model or Home Assistant requests.

OpenCode does not use the failed Codex/bwrap inner sandbox. The checks below
prove only the declared container UID/file/mount boundary, not network isolation.
"""

import errno
import json
import os
import stat
import subprocess
import sys
from pathlib import Path

from runtime_config import (MODEL, OPENCODE_VERSION, build_environment,
                            build_runtime_config)

VERSION = OPENCODE_VERSION
MAX_CONFIG_OUTPUT = 256 * 1024
FORBIDDEN_MOUNTS = {
    "/config", "/homeassistant", "/addons", "/share", "/ssl", "/media",
    "/backup", "/backups", "/run/docker.sock", "/var/run/docker.sock",
    "/app_configs", "/addon_configs", "/local_apps", "/run/dbus",
}
EXECUTABLES = (
    "/usr/local/bin/opencode", "/usr/local/bin/opencode-session",
    "/usr/sbin/nginx", "/sbin/su-exec", "/usr/bin/ttyd", "/usr/bin/python3",
)


class ReadinessError(RuntimeError):
    pass


def mount_boundary_ok(text):
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 6:
            return False
        mountpoint = fields[4].replace("\\040", " ")
        if any(mountpoint == path or mountpoint.startswith(path + "/")
               for path in FORBIDDEN_MOUNTS):
            return False
    return bool(text.strip())


def unprivileged_status_ok(text):
    rows = {parts[0]: parts[1].strip() for line in text.splitlines()
            if len(parts := line.split(":", 1)) == 2}
    try:
        return int(rows["CapEff"], 16) == 0 and rows["NoNewPrivs"] == "1"
    except (KeyError, ValueError):
        return False


def probe():
    if os.getuid() != 1000 or os.getgid() != 1000:
        return False
    if not mount_boundary_ok(Path("/proc/self/mountinfo").read_text()):
        return False
    if not unprivileged_status_ok(Path("/proc/self/status").read_text()):
        return False
    managed = Path("/etc/opencode/opencode.json")
    if not protected_metadata_ok(managed.stat()) or os.access(managed, os.W_OK):
        return False
    for filename in ("/run/sunfish-opencode-home", "/run/sunfish-opencode-config",
                     "/run/sunfish-opencode-config/opencode", "/etc/opencode"):
        directory = Path(filename)
        metadata = directory.stat()
        if (directory.is_symlink() or metadata.st_uid != 0 or metadata.st_gid != 0
                or metadata.st_mode & 0o022 or os.access(directory, os.W_OK)):
            return False
    # Effective open denial is stronger than simply checking the mode bits.
    try:
        descriptor = os.open("/data/options.json", os.O_RDONLY | os.O_NOFOLLOW)
    except PermissionError:
        return True
    except OSError:
        # Missing/symlink/unexpected files are not accepted as proof of protection.
        return False
    else:
        os.close(descriptor)
        return False


def protected_metadata_ok(metadata, capabilities=b""):
    return (stat.S_ISREG(metadata.st_mode) and metadata.st_uid == 0 and metadata.st_gid == 0
            and not metadata.st_mode & (0o022 | stat.S_ISUID | stat.S_ISGID)
            and not capabilities)


def executable_boundary_ok():
    for filename in EXECUTABLES:
        path = Path(filename).resolve(strict=True)
        metadata = path.stat()
        try:
            capabilities = os.getxattr(path, "security.capability")
        except OSError as error:
            if error.errno not in {errno.ENODATA, errno.ENOTSUP}:
                return False
            capabilities = b""
        if not protected_metadata_ok(metadata, capabilities) or not metadata.st_mode & 0o111:
            return False
    return True


def run_check(label, command, environment, runner=subprocess.run, version=False,
              output_check=None, output_failure="READINESS_OUTPUT_MISMATCH"):
    result = None
    category = None
    try:
        result = runner(command, env=environment, cwd="/data/workspace",
                        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE, timeout=20, check=False)
        ok = result.returncode == 0
        if version:
            ok = ok and result.stdout.decode("utf-8", "replace").strip() == VERSION
        if ok and output_check is not None:
            try:
                ok = output_check(result.stdout) is True
            except (ValueError, TypeError, UnicodeError):
                ok = False
            if not ok:
                category = output_failure
    except FileNotFoundError:
        category, ok = "EXECUTABLE_NOT_FOUND", False
    except subprocess.TimeoutExpired:
        category, ok = "PROCESS_TIMEOUT", False
    except OSError:
        category, ok = "PROCESS_START_FAILED", False
    print("Readiness " + label + (": PASS" if ok else ": FAIL"), flush=True)
    if not ok:
        raw_error = getattr(result, "stderr", b"") or b""
        if category is None:
            if b"Permission denied" in raw_error:
                category = "PERMISSION_DENIED"
            elif b"Operation not permitted" in raw_error:
                category = "OPERATION_NOT_PERMITTED"
            elif b"map_hash" in raw_error:
                category = "NGINX_MAP_HASH_SIZE"
            elif b"unknown directive" in raw_error:
                category = "NGINX_UNKNOWN_DIRECTIVE"
            elif b"No such file or directory" in raw_error:
                category = "MISSING_RUNTIME_PATH"
            elif b"invalid" in raw_error or b"unexpected" in raw_error:
                category = "CONFIGURATION_SYNTAX"
            else:
                category = "UNSPECIFIED_NONZERO_EXIT"
        print("Readiness failure category: " + category, flush=True)
        raise ReadinessError("Isolated OpenCode compatibility check failed")


def offline_probe_environment(directory):
    """No persistent auth, account, model cache, or caller-supplied environment.

    v1.18.34 models-dev.ts reads its disk cache before its embedded snapshot.
    init.py must create a *fresh* directory before using this environment. HOME
    and XDG_CONFIG_HOME remain the audited, root-owned, nonwritable locations.
    """
    environment = build_environment()
    for key, suffix in (("XDG_DATA_HOME", "data"), ("XDG_CACHE_HOME", "cache"),
                        ("XDG_STATE_HOME", "state"), ("TMPDIR", "tmp")):
        environment[key] = str(Path(directory) / suffix)
    return environment


def model_catalog_matches(output):
    # The pinned models command has no inference path. Never use --refresh.
    if not isinstance(output, bytes) or len(output) > 128:
        return False
    try:
        return output.decode("utf-8", "strict").strip() == MODEL
    except UnicodeError:
        return False


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate configuration key")
        result[key] = value
    return result


def _invalid_json_constant(_value):
    raise ValueError("Non-JSON configuration constant")


def _ordered_policy_equal(actual, expected, path=()):
    """Strict types and values; permission order must survive native parsing."""
    if type(actual) is not type(expected):
        return False
    if isinstance(expected, dict):
        if actual.keys() != expected.keys():
            return False
        if "permission" in path and list(actual) != list(expected):
            return False
        return all(_ordered_policy_equal(actual[key], value, (*path, key))
                   for key, value in expected.items())
    if isinstance(expected, list):
        return (len(actual) == len(expected)
                and all(_ordered_policy_equal(a, b, path) for a, b in zip(actual, expected)))
    return actual == expected


def resolved_config_matches(output, enable_mcp=False):
    """Validate actual `debug config` output against v1.18.34 normalization.

    The pinned Config loader derives empty mode/command objects and a username;
    ConfigAgentV1 adds empty options and permissions to each agent. No other
    extra field, provider option, plugin, credential, agent, or permission is
    accepted. Native stdout/stderr are never printed, even on invalid JSON.
    """
    if not isinstance(enable_mcp, bool):
        return False
    if not isinstance(output, bytes) or len(output) > MAX_CONFIG_OUTPUT:
        return False
    try:
        actual = json.loads(output.decode("utf-8", "strict"), object_pairs_hook=_unique_object,
                            parse_constant=_invalid_json_constant)
    except (ValueError, UnicodeError):
        return False
    if not isinstance(actual, dict):
        return False
    expected = build_runtime_config(enable_mcp=enable_mcp)
    expected.update({"mode": {}, "command": {}, "username": "opencode"})
    for agent in expected["agent"].values():
        agent.setdefault("options", {})
        agent.setdefault("permission", {})
    if "plugin_origins" in actual:
        expected["plugin_origins"] = []
    return _ordered_policy_equal(actual, expected)


def run_offline_catalog_readiness(environment, runner=subprocess.run):
    run_check("embedded Big Pickle-only model catalog (no refresh/inference)",
              unprivileged_command("/usr/local/bin/opencode", "--pure", "models", "opencode"),
              environment, runner=runner, output_check=model_catalog_matches,
              output_failure="EMBEDDED_MODEL_CATALOG_MISMATCH")
    run_config_readiness(environment, enable_mcp=False, runner=runner)


def run_config_readiness(environment, enable_mcp=False, runner=subprocess.run):
    label = ("native managed ten-tool read-only schema/policy (relay not started)"
             if enable_mcp else "native offline deny-all/no-MCP schema/policy")
    run_check(label,
              unprivileged_command("/usr/local/bin/opencode", "--pure", "debug", "config"),
              environment, runner=runner,
              output_check=lambda output: resolved_config_matches(output, enable_mcp=enable_mcp),
              output_failure="RESOLVED_CONFIGURATION_POLICY_MISMATCH")


def run_readiness(environment):
    try:
        binaries_ok = executable_boundary_ok()
    except OSError:
        binaries_ok = False
    print("Readiness root-owned executable/no-setuid/no-file-capability boundary: "
          + ("PASS" if binaries_ok else "FAIL"), flush=True)
    if not binaries_ok:
        raise ReadinessError("Executable ownership or privilege check failed")
    run_check("pinned OpenCode version", unprivileged_command(
              "/usr/local/bin/opencode", "--version"), environment, version=True)
    run_check("UID1000/no-HA-mount/root-options-unreadable/readonly-managed-config boundary",
              unprivileged_command("/usr/bin/python3", "/opt/sunfish/readiness.py", "--probe"), environment)


def unprivileged_command(program, *arguments):
    return ["/usr/bin/python3", "/opt/sunfish/unprivileged_exec.py", program, *arguments]


if __name__ == "__main__":
    if sys.argv[1:] != ["--probe"]:
        raise SystemExit(2)
    try:
        raise SystemExit(0 if probe() else 1)
    except Exception:
        raise SystemExit(1)
