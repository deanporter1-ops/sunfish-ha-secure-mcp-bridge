"""Offline readiness/source regressions, not a Linux runtime proof."""

import contextlib
import copy
import importlib.util
import io
import json
import stat
import subprocess
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).parents[1]))
from readiness import (ReadinessError, mount_boundary_ok, protected_metadata_ok,
                       model_catalog_matches, offline_probe_environment,
                       resolved_config_matches, run_check, run_config_readiness,
                       run_offline_catalog_readiness, unprivileged_status_ok)
from runtime_config import (AGENT_NAME, MCP_NAME, MODEL, build_environment,
                            build_runtime_config)

BASE = Path(__file__).parents[1]


def native_config_fixture(enable_mcp=False):
    """Documented v1.18.34 Config/ConfigAgentV1 debug-output derivations."""
    config = build_runtime_config(enable_mcp)
    config.update({"mode": {}, "command": {}, "username": "opencode"})
    for agent in config["agent"].values():
        agent.setdefault("options", {})
        agent.setdefault("permission", {})
    return config


def encode_config(config):
    return json.dumps(config).encode("utf-8")


class ReadinessTests(unittest.TestCase):
    def test_no_host_or_ha_mounts(self):
        plain = "1 0 0:1 / / rw - overlay overlay rw\n2 1 0:2 / /data rw - ext4 mock rw"
        self.assertTrue(mount_boundary_ok(plain))
        for target in ("/config", "/homeassistant", "/addons", "/ssl", "/media", "/backups",
                       "/share/nested", "/var/run/docker.sock", "/run/dbus"):
            self.assertFalse(mount_boundary_ok(plain + "\n3 1 0:3 / " + target + " rw - ext4 mock rw"))
        self.assertFalse(mount_boundary_ok("malformed"))
        self.assertFalse(mount_boundary_ok(""))

    def test_no_effective_capabilities(self):
        self.assertTrue(unprivileged_status_ok("Name:\tpython\nCapEff:\t0000000000000000\nNoNewPrivs:\t1\n"))
        for value in ("", "CapEff: bad-value", "CapEff: 0000000000000001\nNoNewPrivs:1",
                      "CapEff:0000000000000000\nNoNewPrivs:0", "CapEff:0000000000000000"):
            self.assertFalse(unprivileged_status_ok(value))

    def test_files_are_root_owned_nonwritable_and_unprivileged(self):
        def metadata(mode=0o755, uid=0, gid=0):
            return SimpleNamespace(st_mode=stat.S_IFREG | mode, st_uid=uid, st_gid=gid)
        self.assertTrue(protected_metadata_ok(metadata()))
        for entry in (metadata(0o777), metadata(0o775), metadata(0o4755), metadata(0o2755),
                      metadata(uid=1000), metadata(gid=1000)):
            self.assertFalse(protected_metadata_ok(entry))
        self.assertFalse(protected_metadata_ok(metadata(), b"capability"))

    def test_readiness_version_exact_and_outputs_never_logged(self):
        for output, accepted in ((b"1.18.34\n", True), (b"1.18.33\n", False),
                                 (b"1.18.34 FAKE_SECRET", False)):
            runner = lambda *_a, **_k: SimpleNamespace(returncode=0, stdout=output, stderr=b"")
            capture = io.StringIO()
            with contextlib.redirect_stdout(capture):
                if accepted:
                    run_check("version", ["ignored"], {}, runner=runner, version=True)
                else:
                    with self.assertRaises(ReadinessError):
                        run_check("version", ["ignored"], {}, runner=runner, version=True)
            self.assertNotIn("FAKE_SECRET", capture.getvalue())

    def test_fixed_exception_categories_no_raw_secret(self):
        for exception, category in ((FileNotFoundError("FAKE_SECRET"), "EXECUTABLE_NOT_FOUND"),
                                    (OSError("FAKE_SECRET"), "PROCESS_START_FAILED"),
                                    (subprocess.TimeoutExpired("FAKE_SECRET", 20), "PROCESS_TIMEOUT")):
            def fail(*_a, **_k):
                raise exception
            capture = io.StringIO()
            with contextlib.redirect_stdout(capture), self.assertRaises(ReadinessError):
                run_check("test", ["ignored"], {}, runner=fail)
            self.assertIn(category, capture.getvalue())
            self.assertNotIn("FAKE_SECRET", capture.getvalue())

    def test_process_check_timeout_cwd_env_contract(self):
        def runner(_command, **kwargs):
            self.assertEqual(kwargs["timeout"], 20)
            self.assertEqual(kwargs["cwd"], "/data/workspace")
            self.assertEqual(kwargs["env"], {"HOME": "/safe"})
            return SimpleNamespace(returncode=1, stdout=b"", stderr=b"invalid FAKE_SECRET")
        capture = io.StringIO()
        with contextlib.redirect_stdout(capture), self.assertRaises(ReadinessError):
            run_check("test", ["ignored"], {"HOME": "/safe"}, runner=runner)
        self.assertIn("CONFIGURATION_SYNTAX", capture.getvalue())
        self.assertNotIn("FAKE_SECRET", capture.getvalue())

    def test_embedded_catalog_has_only_exact_big_pickle(self):
        for output in (b"opencode/big-pickle\n", b"opencode/big-pickle\r\n"):
            self.assertTrue(model_catalog_matches(output))
        for output in (b"", b"opencode/other\n", b"opencode/big-pickle\nopencode/paid\n",
                       b"opencode/big-pickle\nopencode/big-pickle\n", b"\xff", MODEL,
                       b"FAKE_SECRET" + b"x" * 200):
            self.assertFalse(model_catalog_matches(output))

    def test_native_schema_output_normalizations_are_version_specific(self):
        for enabled in (False, True):
            fixture = native_config_fixture(enabled)
            self.assertTrue(resolved_config_matches(encode_config(fixture), enabled))
            fixture["plugin_origins"] = []
            self.assertTrue(resolved_config_matches(encode_config(fixture), enabled))
            fixture["plugin_origins"] = [{"spec": "unreviewed-plugin"}]
            self.assertFalse(resolved_config_matches(encode_config(fixture), enabled))
        self.assertFalse(resolved_config_matches(encode_config(build_runtime_config(False))))
        self.assertFalse(resolved_config_matches(encode_config(native_config_fixture()), "false"))

    def test_policy_rejects_extra_or_relaxed_loaded_fields(self):
        fixture = native_config_fixture(True)
        mutations = [
            lambda c: c.update(model="opencode/paid"),
            lambda c: c.update(small_model="opencode/paid"),
            lambda c: c.update(enabled_providers=["opencode", "openai"]),
            lambda c: c["provider"]["opencode"].update(whitelist=["big-pickle", "paid"]),
            lambda c: c["provider"]["opencode"].update(options={"apiKey": "FAKE_SECRET"}),
            lambda c: c["provider"].update(openai={}),
            lambda c: c.update(default_agent="build"),
            lambda c: c.update(autoupdate=True),
            lambda c: c.update(share="auto"),
            lambda c: c.update(snapshot=True),
            lambda c: c.update(plugin=["arbitrary-plugin"]),
            lambda c: c.update(lsp={}),
            lambda c: c.update(formatter=True),
            lambda c: c.update(subagent_depth=True),  # bool must not compare equal to integer 0/1.
            lambda c: c.update(subagent_depth=0.0),
            lambda c: c.update(shell="/bin/bash"),
            lambda c: c.update(instructions=["external-instructions"]),
            lambda c: c.update(tools={"bash": True}),
            lambda c: c.update(command={"unsafe": {"template": "unsafe"}}),
            lambda c: c.update(username="root"),
            lambda c: c["agent"]["build"].update(disable=False),
            lambda c: c["agent"].update(unreviewed={"permission": {"*": "allow"}}),
            lambda c: c["agent"]["title"].update(model="opencode/paid"),
            lambda c: c["agent"][AGENT_NAME].update(mode="all"),
            lambda c: c["agent"][AGENT_NAME].update(options={"apiKey": "***"}),
            lambda c: c["agent"][AGENT_NAME]["permission"].update(bash="allow"),
            lambda c: c["permission"].update(bash="ask"),
            lambda c: c["permission"].update({"*": "allow"}),
            lambda c: c["permission"].update({MCP_NAME + "_ha_call_service": "allow"}),
            lambda c: c["permission"]["external_directory"].update({"*": "allow"}),
            lambda c: c["mcp"][MCP_NAME].update(url="https://FAKE_SECRET.invalid/mcp"),
            lambda c: c["mcp"][MCP_NAME].update(oauth=True),
            lambda c: c["mcp"][MCP_NAME].update(headers={"Authorization": "***"}),
            lambda c: c["mcp"].update(unreviewed={"type": "local", "command": ["/bin/sh"]}),
        ]
        for index, mutate in enumerate(mutations):
            with self.subTest(mutation=index):
                config = copy.deepcopy(fixture)
                mutate(config)
                self.assertFalse(resolved_config_matches(encode_config(config), True))

    def test_permission_precedence_must_survive_native_schema(self):
        for location in ("global", "agent", "external"):
            config = native_config_fixture(True)
            if location == "global":
                config["permission"] = dict(reversed(list(config["permission"].items())))
            elif location == "agent":
                agent = config["agent"][AGENT_NAME]
                agent["permission"] = dict(reversed(list(agent["permission"].items())))
            else:
                policy = config["permission"]
                policy["external_directory"] = dict(reversed(list(policy["external_directory"].items())))
            self.assertFalse(resolved_config_matches(encode_config(config), True))

    def test_invalid_or_ambiguous_config_json_is_denied(self):
        for output in (b"not JSON FAKE_SECRET", b"[]", b"null", b"\xff", b"{}" * 140000,
                       b'{"model":"first","model":"second"}', b'{"subagent_depth":NaN}',
                       b'{"subagent_depth":Infinity}', "not bytes"):
            self.assertFalse(resolved_config_matches(output))
        self.assertFalse(resolved_config_matches(encode_config(native_config_fixture(True)), False))
        self.assertFalse(resolved_config_matches(encode_config(native_config_fixture(False)), True))

    def test_probe_environment_uses_fresh_storage_and_no_inherited_auth(self):
        with patch.dict("os.environ", {"OPENAI_API_KEY": "FAKE_SECRET", "OPENCODE_PERMISSION": "allow",
                                       "OPENCODE_MODELS_PATH": "/unreviewed/models.json"}):
            environment = offline_probe_environment("/run/fresh-probe")
        for variable, directory in (("XDG_DATA_HOME", "data"), ("XDG_CACHE_HOME", "cache"),
                                    ("XDG_STATE_HOME", "state"), ("TMPDIR", "tmp")):
            # as_posix() also normalizes the offline Windows test fixture.
            self.assertEqual(Path(environment[variable]).as_posix(), "/run/fresh-probe/" + directory)
        for key in ("HOME", "XDG_CONFIG_HOME", "OPENCODE_CONFIG"):
            self.assertEqual(environment[key], build_environment()[key])
        for key in ("OPENAI_API_KEY", "OPENCODE_PERMISSION", "OPENCODE_MODELS_PATH", "OPENCODE_CONFIG_CONTENT"):
            self.assertNotIn(key, environment)
        self.assertEqual(environment["OPENCODE_DISABLE_MODELS_FETCH"], "1")

    def test_native_probes_have_no_login_prompt_model_run_or_refresh(self):
        calls = []
        def runner(command, **kwargs):
            calls.append(command)
            self.assertEqual(kwargs["stdin"], subprocess.DEVNULL)
            self.assertEqual(kwargs["timeout"], 20)
            if command[-2:] == ["models", "opencode"]:
                output = b"opencode/big-pickle\n"
            else:
                output = encode_config(native_config_fixture(len(calls) == 3))
            return SimpleNamespace(returncode=0, stdout=output, stderr=b"FAKE_SECRET")
        capture = io.StringIO()
        with contextlib.redirect_stdout(capture):
            run_offline_catalog_readiness({}, runner=runner)
            run_config_readiness({}, enable_mcp=True, runner=runner)
        self.assertEqual([call[3:] for call in calls], [
            ["--pure", "models", "opencode"], ["--pure", "debug", "config"],
            ["--pure", "debug", "config"],
        ])
        for call in calls:
            self.assertEqual(call[:3], ["/usr/bin/python3", "/opt/sunfish/unprivileged_exec.py",
                                       "/usr/local/bin/opencode"])
            for denied in ("--refresh", "run", "login", "--prompt", "--dangerously-skip-permissions"):
                self.assertNotIn(denied, call)
        self.assertNotIn("FAKE_SECRET", capture.getvalue())

    def test_invalid_native_outputs_fail_closed_without_logging(self):
        for function, category in ((run_offline_catalog_readiness, "EMBEDDED_MODEL_CATALOG_MISMATCH"),
                                   (run_config_readiness, "RESOLVED_CONFIGURATION_POLICY_MISMATCH")):
            runner = lambda *_a, **_k: SimpleNamespace(returncode=0, stdout=b"FAKE_SECRET", stderr=b"FAKE_SECRET")
            capture = io.StringIO()
            with contextlib.redirect_stdout(capture), self.assertRaises(ReadinessError):
                function({}, runner=runner)
            self.assertIn(category, capture.getvalue())
            self.assertNotIn("FAKE_SECRET", capture.getvalue())

    def test_startup_config_sequence_and_failure_stop_before_final_policy(self):
        spec = importlib.util.spec_from_file_location("isolated_init_test", BASE / "init.py")
        initializer = importlib.util.module_from_spec(spec)
        with patch.dict(sys.modules, {"pwd": SimpleNamespace()}):
            spec.loader.exec_module(initializer)
        user = SimpleNamespace(pw_uid=1000, pw_gid=1000)
        temporary = MagicMock()
        temporary.__enter__.return_value = "/run/fresh-probe"
        writes, events = [], []
        def write(_path, content, *_args):
            config = json.loads(content)
            writes.append(config)
            events.append("write-mcp" if "mcp" in config else "write-offline")
        def offline(environment):
            self.assertEqual(writes[-1], build_runtime_config(False))
            self.assertNotIn("mcp", writes[-1])
            self.assertNotIn("/data/opencode/", environment["XDG_DATA_HOME"])
            events.append("offline-check")
        def final(_environment, enable_mcp):
            self.assertTrue(enable_mcp)
            self.assertEqual(writes[-1], build_runtime_config(True))
            events.append("final-check")
        with patch.object(initializer.tempfile, "TemporaryDirectory", return_value=temporary) as factory, \
             patch.object(initializer, "ensure_directory") as ensure, \
             patch.object(initializer, "protected_write", side_effect=write), \
             patch.object(initializer, "run_offline_catalog_readiness", side_effect=offline), \
             patch.object(initializer, "run_config_readiness", side_effect=final):
            initializer.validate_native_configuration(True, user)
            factory.assert_called_once_with(prefix="sunfish-opencode-readiness-", dir="/run")
            self.assertEqual(ensure.call_args_list[0].args, ("/run/fresh-probe", 0, 0, 0o755))
            for call in ensure.call_args_list[1:]:
                self.assertEqual(call.args[1:], (1000, 1000, 0o700))
        self.assertEqual(events, ["write-offline", "offline-check", "write-mcp", "final-check"])
        with patch.object(initializer.tempfile, "TemporaryDirectory", return_value=temporary), \
             patch.object(initializer, "ensure_directory"), \
             patch.object(initializer, "protected_write") as writer, \
             patch.object(initializer, "run_offline_catalog_readiness", side_effect=ReadinessError()), \
             patch.object(initializer, "run_config_readiness") as final_checker:
            with self.assertRaises(ReadinessError):
                initializer.validate_native_configuration(True, user)
            self.assertEqual(writer.call_count, 1)
            self.assertNotIn("mcp", json.loads(writer.call_args.args[1]))
            final_checker.assert_not_called()
        source = (BASE / "init.py").read_text()
        self.assertLess(source.index("validate_native_configuration(enable_mcp=bool"),
                        source.index('relay = make_server(options["mcp_url"])'))

    def test_absolute_alpine_commands_and_no_bwrap_probe(self):
        source = ((BASE / "init.py").read_text() + (BASE / "readiness.py").read_text()
                  + (BASE / "unprivileged_exec.py").read_text())
        for command in ("/usr/sbin/nginx", "/sbin/su-exec", "/usr/bin/ttyd"):
            self.assertIn(command, source)
        self.assertNotIn('"codex", "sandbox"', source)
        self.assertNotIn('"/usr/local/bin/bwrap"', source)
        self.assertIn("os.environ.clear()", source)
        self.assertIn("os.O_NOFOLLOW", source)
        self.assertIn("os.chmod(options_path, 0o600)", source)
        self.assertIn('os.chmod("/data", 0o711)', source)

    def test_no_new_privs_wrapper_before_su_exec(self):
        source = (BASE / "unprivileged_exec.py").read_text()
        self.assertIn("PR_SET_NO_NEW_PRIVS = 38", source)
        self.assertIn("PR_GET_NO_NEW_PRIVS = 39", source)
        self.assertIn("libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)", source)
        self.assertIn('os.execve("/sbin/su-exec"', source)
        self.assertLess(source.index("libc.prctl(PR_SET_NO_NEW_PRIVS"), source.index('os.execve("/sbin/su-exec"'))
        self.assertNotIn("preexec_fn=", (BASE / "init.py").read_text())

    def test_manifest_requests_no_escalation(self):
        source = (BASE / "config.yaml").read_text()
        for setting in ("boot: manual", "map: []", "ports: {}", "apparmor: true", "privileged: []",
                        "devices: []", "full_access: false", "hassio_api: false", "homeassistant_api: false",
                        "docker_api: false", "host_network: false", "host_pid: false", "host_ipc: false"):
            self.assertIn(setting, source)

    def test_ingress_source_and_identity_gates_stay_fail_closed(self):
        source = (BASE / "nginx.conf").read_text()
        self.assertIn("allow 172.30.32.2;", source)
        self.assertIn("deny all;", source)
        self.assertIn("default 0;", source)
        self.assertIn("~^__ALLOWED_USER_ID__$ 1;", source)
        self.assertIn("if ($opencode_allowed_user = 0) { return 403; }", source)
        self.assertIn("proxy_pass http://127.0.0.1:7681;", source)


if __name__ == "__main__":
    unittest.main()
