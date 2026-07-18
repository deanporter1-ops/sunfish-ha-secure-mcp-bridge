import importlib.util
import json
import pathlib
import unittest


MODULE_PATH = pathlib.Path(__file__).parents[1] / "sunfish_secure_mcp_bridge" / "bridge.py"
SPEC = importlib.util.spec_from_file_location("bridge", MODULE_PATH)
bridge = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(bridge)


class PolicyTests(unittest.TestCase):
    def test_exact_tool_count(self):
        self.assertEqual(len(bridge.ALLOWED_TOOLS), 45)

    def test_read_tool_allowed(self):
        self.assertTrue(bridge.tool_allowed("ha_get_state", {})[0])

    def test_unlisted_tool_denied(self):
        self.assertFalse(bridge.tool_allowed("ha_remove_entity", {})[0])

    def test_backup_create_allowed(self):
        self.assertTrue(
            bridge.tool_allowed("ha_manage_backup", {"scope": "snapshot", "action": "create"})[0]
        )

    def test_backup_restore_and_delete_denied(self):
        for action in ("restore", "delete"):
            self.assertFalse(
                bridge.tool_allowed("ha_manage_backup", {"scope": "snapshot", "action": action})[0]
            )

    def test_restart_service_denied(self):
        self.assertFalse(
            bridge.tool_allowed(
                "ha_call_service",
                {"domain": "homeassistant", "service": "restart"},
            )[0]
        )

    def test_script_activation_denied(self):
        self.assertFalse(
            bridge.tool_allowed(
                "ha_call_service",
                {"domain": "script", "service": "turn_on", "entity_id": "script.anything"},
            )[0]
        )

    def test_unsafe_automation_action_denied(self):
        self.assertFalse(
            bridge.tool_allowed(
                "ha_config_set_automation",
                {
                    "config": {
                        "alias": "Unsafe",
                        "triggers": [],
                        "actions": [{"action": "homeassistant.restart"}],
                    }
                },
            )[0]
        )

    def test_safe_automation_action_allowed(self):
        self.assertTrue(
            bridge.tool_allowed(
                "ha_config_set_automation",
                {
                    "config": {
                        "alias": "Curtains",
                        "triggers": [],
                        "actions": [
                            {
                                "action": "cover.close_cover",
                                "target": {"entity_id": "cover.living_room_curtains"},
                            }
                        ],
                    }
                },
            )[0]
        )

    def test_python_transform_denied(self):
        self.assertFalse(
            bridge.tool_allowed(
                "ha_config_set_script",
                {"script_id": "x", "python_transform": "config.clear()"},
            )[0]
        )

    def test_cover_stop_allowed(self):
        self.assertTrue(
            bridge.tool_allowed(
                "ha_call_service",
                {"domain": "cover", "service": "stop_cover", "entity_id": "cover.living_room_curtains"},
            )[0]
        )

    def test_infrastructure_switch_denied(self):
        self.assertFalse(
            bridge.tool_allowed(
                "ha_call_service",
                {"domain": "switch", "service": "turn_off", "entity_id": "switch.zigbee2mqtt"},
            )[0]
        )

    def test_integration_add_and_disable_denied(self):
        self.assertFalse(bridge.tool_allowed("ha_set_integration", {"domain": "workday"})[0])
        self.assertFalse(
            bridge.tool_allowed("ha_set_integration", {"entry_id": "abc", "enabled": False})[0]
        )

    def test_integration_options_update_allowed(self):
        self.assertTrue(
            bridge.tool_allowed("ha_set_integration", {"entry_id": "abc", "config": {"scan_interval": 30}})[0]
        )

    def test_tools_list_is_filtered_and_schema_narrowed(self):
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "tools": [
                    {"name": "ha_get_state", "description": "Read", "inputSchema": {"type": "object"}},
                    {
                        "name": "ha_manage_backup",
                        "description": "Backup",
                        "inputSchema": {
                            "type": "object",
                            "properties": {"action": {"enum": ["create", "restore", "delete"]}},
                        },
                    },
                    {"name": "ha_remove_entity", "description": "Delete", "inputSchema": {"type": "object"}},
                ]
            },
        }
        filtered = json.loads(bridge.filter_response(json.dumps(payload).encode(), "application/json"))
        tools = filtered["result"]["tools"]
        self.assertEqual([tool["name"] for tool in tools], ["ha_get_state", "ha_manage_backup"])
        self.assertEqual(
            tools[1]["inputSchema"]["properties"]["action"]["enum"],
            ["create", "list", "view", "diff"],
        )


if __name__ == "__main__":
    unittest.main()
