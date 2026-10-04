"""Offline policy and source-contract tests; no HA, cloud, or credentials."""

import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parents[1]))

from mcp_proxy import ALLOWED_TOOLS, PolicyError, check_request, scrub
from runtime_config import (
    AGENT_NAME, HOME, MANAGED_CONFIG_PATH, MCP_LOOPBACK_URL, MCP_NAME, MODEL,
    OPENCODE_VERSION, ROOT_DIRECTORIES, TRUNCATION_GLOB, USER_DIRECTORIES,
    WORKSPACE, XDG_CONFIG_HOME, build_environment, build_runtime_config,
    permission_policy, session_command,
)
from security import identity_allowed, render_nginx_config, validate_user_id


class RuntimePolicyTests(unittest.TestCase):
    def test_version_and_both_model_paths_are_fixed(self):
        config = build_runtime_config()
        self.assertEqual(OPENCODE_VERSION, "1.18.34")
        self.assertEqual(config["model"], "opencode/big-pickle")
        self.assertEqual(config["small_model"], MODEL)
        self.assertEqual(config["enabled_providers"], ["opencode"])
        self.assertEqual(config["provider"], {"opencode": {"whitelist": ["big-pickle"]}})
        self.assertNotIn("apiKey", json.dumps(config))
        for name in (AGENT_NAME, "title", "summary", "compaction"):
            self.assertEqual(config["agent"][name]["model"], MODEL)

    def test_exact_ten_tool_exceptions_and_no_broad_allow(self):
        policy = permission_policy()
        expected = {MCP_NAME + "_" + tool for tool in ALLOWED_TOOLS}
        self.assertEqual(len(expected), 10)
        self.assertEqual({key for key, value in policy.items() if value == "allow"}, expected)
        self.assertEqual(next(iter(policy)), "*")
        self.assertEqual(policy["*"], "deny")
        self.assertNotIn(MCP_NAME + "_*", policy)
        for key in ("bash", "edit", "task"):
            self.assertEqual(policy[key], "deny")
        self.assertEqual(policy["external_directory"], {"*": "deny", TRUNCATION_GLOB: "deny"})
        self.assertEqual(build_runtime_config()["agent"][AGENT_NAME]["permission"], policy)

    def test_old_primary_and_subagents_cannot_be_selected(self):
        config = build_runtime_config()
        self.assertEqual(config["default_agent"], AGENT_NAME)
        self.assertEqual(config["agent"][AGENT_NAME]["mode"], "primary")
        self.assertEqual(config["subagent_depth"], 0)
        for name in ("build", "plan", "general", "explore"):
            self.assertTrue(config["agent"][name]["disable"])

    def test_remote_loopback_shape_and_oauth_disabled(self):
        self.assertEqual(build_runtime_config()["mcp"], {MCP_NAME: {
            "type": "remote", "url": MCP_LOOPBACK_URL, "enabled": True,
            "oauth": False, "timeout": 120000,
        }})
        self.assertNotIn("enabled_tools", json.dumps(build_runtime_config()))

    def test_offline_probe_config_has_no_mcp_or_tool_allow(self):
        config = build_runtime_config(enable_mcp=False)
        self.assertNotIn("mcp", config)
        self.assertFalse(any(value == "allow" for value in config["permission"].values()))
        for value in (None, "yes", 1):
            with self.subTest(value=value), self.assertRaises(ValueError):
                build_runtime_config(value)

    def test_disabled_update_sharing_plugins_and_lsp(self):
        config = build_runtime_config()
        self.assertFalse(config["autoupdate"])
        self.assertEqual(config["share"], "disabled")
        self.assertEqual(config["plugin"], [])
        self.assertFalse(config["lsp"])
        self.assertFalse(config["formatter"])
        self.assertFalse(config["snapshot"])

    def test_returned_policy_objects_do_not_leak_mutations(self):
        first = build_runtime_config()
        first["permission"]["bash"] = "allow"
        first["agent"][AGENT_NAME]["permission"]["edit"] = "allow"
        first["provider"]["opencode"]["whitelist"].append("paid-model")
        second = build_runtime_config()
        self.assertEqual(second["permission"]["bash"], "deny")
        self.assertEqual(second["agent"][AGENT_NAME]["permission"]["edit"], "deny")
        self.assertEqual(second["provider"]["opencode"]["whitelist"], ["big-pickle"])


class EnvironmentAndLaunchTests(unittest.TestCase):
    def test_clean_environment_does_not_inherit_host_or_api_secrets(self):
        with patch.dict(os.environ, {"SUPERVISOR_TOKEN": "fake-secret", "OPENAI_API_KEY": "fake-paid-key",
                                    "OPENCODE_CONFIG_CONTENT": "unsafe", "OPENCODE_PERMISSION": "unsafe"}):
            environment = build_environment()
        for name in ("SUPERVISOR_TOKEN", "OPENAI_API_KEY", "OPENCODE_API_KEY", "ANTHROPIC_API_KEY",
                     "OPENCODE_CONFIG_CONTENT", "OPENCODE_PERMISSION", "OPENCODE_TEST_MANAGED_CONFIG_DIR"):
            self.assertNotIn(name, environment)
        self.assertNotIn("fake-secret", json.dumps(environment))
        self.assertEqual(environment["OPENCODE_CONFIG"], MANAGED_CONFIG_PATH)
        self.assertEqual(environment["HOME"], HOME)
        self.assertEqual(environment["XDG_CONFIG_HOME"], XDG_CONFIG_HOME)

    def test_environment_security_flags_are_explicit(self):
        environment = build_environment()
        for key in ("OPENCODE_DISABLE_PROJECT_CONFIG", "OPENCODE_DISABLE_AUTOUPDATE", "OPENCODE_DISABLE_SHARE",
                    "OPENCODE_DISABLE_MODELS_FETCH"):
            self.assertEqual(environment[key], "1")
        for key in ("OPENCODE_DISABLE_DEFAULT_PLUGINS", "OPENCODE_PURE", "OPENCODE_DISABLE_EXTERNAL_SKILLS",
                    "OPENCODE_DISABLE_CLAUDE_CODE", "OPENCODE_DISABLE_LSP_DOWNLOAD"):
            self.assertEqual(environment[key], "true")

    def test_readonly_home_and_config_are_distinct_from_persistent_user_data(self):
        self.assertIn(HOME, ROOT_DIRECTORIES)
        self.assertIn(XDG_CONFIG_HOME + "/opencode", ROOT_DIRECTORIES)
        self.assertIn("/etc/opencode", ROOT_DIRECTORIES)
        self.assertIn(WORKSPACE, USER_DIRECTORIES)
        self.assertTrue(all(path.startswith("/run/") or path.startswith("/etc/") for path in ROOT_DIRECTORIES))
        self.assertTrue(all(path.startswith("/data/") for path in USER_DIRECTORIES))
        self.assertTrue(set(ROOT_DIRECTORIES).isdisjoint(USER_DIRECTORIES))
        self.assertEqual(TRUNCATION_GLOB, "/data/opencode/data/opencode/tool-output/*")

    def test_launcher_is_pinned_and_starts_no_prompt_login_or_listener(self):
        command = session_command()
        self.assertEqual(command, ["/usr/local/bin/opencode", "--pure", "--model", MODEL, "--agent", AGENT_NAME])
        launcher = (Path(__file__).parents[1] / "opencode-session").read_text()
        self.assertIn("exec " + " ".join(command), launcher)
        self.assertIn("cd " + WORKSPACE, launcher)
        for forbidden in ("--auto", "--yolo", "--dangerously-skip-permissions", "--prompt", "--port", "--hostname",
                          "auth login", "--device-auth", "SUPERVISOR_TOKEN", "mcp_url"):
            self.assertNotIn(forbidden, launcher)
        self.assertIn("data may be used to improve", launcher)


class ServerPolicyTests(unittest.TestCase):
    def test_exact_reads_permitted_but_control_and_config_denied(self):
        for name in ALLOWED_TOOLS:
            request = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": name, "arguments": {}}}
            self.assertEqual(check_request(request), "tools/call")
        for name in ("ha_call_service", "ha_set_state", "ha_config_set_automation", "ha_install_addon", "ha_run_script"):
            with self.subTest(name=name), self.assertRaises(PolicyError):
                check_request({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": name, "arguments": {}}})

    def test_batch_subscriptions_and_arbitrary_resource_reads_denied(self):
        for request in ([{"jsonrpc": "2.0", "id": 1, "method": "ping"}],
                        {"jsonrpc": "2.0", "id": 1, "method": "resources/subscribe", "params": {"uri": "secret"}},
                        {"jsonrpc": "2.0", "id": 1, "method": "resources/read", "params": {"uri": "file:///data/options.json"}}):
            with self.subTest(request=request), self.assertRaises(PolicyError):
                check_request(request)

    def test_secret_fields_scrubbed_in_structured_and_embedded_text(self):
        secret = "never-disclose-fake"
        for key in ("password", "access_token", "mqtt_password", "install_code"):
            value = {key: secret, "text": json.dumps({key: secret}), "state": "on"}
            output = json.dumps(scrub(value, []))
            self.assertNotIn(secret, output)
            self.assertIn("on", output)


class OwnerIdentityTests(unittest.TestCase):
    def test_owner_is_exact_and_malformed_inputs_fail_closed(self):
        owner = "a1" * 16
        self.assertEqual(validate_user_id(owner), owner)
        self.assertTrue(identity_allowed(owner, owner))
        for value in (None, "", owner.upper(), owner + "\n", owner + "," + owner, " " + owner):
            with self.subTest(value=value):
                self.assertFalse(identity_allowed(value, owner))
        for invalid in (None, "", "a" * 31, "g" * 32, owner + "; allow all;"):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                validate_user_id(invalid)

    def test_owner_template_replace_is_narrow(self):
        template = "map $http_x_remote_user_id $allowed { default 0; ~^__ALLOWED_USER_ID__$ 1; }"
        owner = "a1" * 16
        rendered = render_nginx_config(template, owner)
        self.assertIn("~^" + owner + "$ 1;", rendered)
        self.assertIn("default 0;", rendered)
        for invalid in ("", template + "__ALLOWED_USER_ID__"):
            with self.assertRaises(ValueError):
                render_nginx_config(invalid, owner)


if __name__ == "__main__":
    unittest.main()
