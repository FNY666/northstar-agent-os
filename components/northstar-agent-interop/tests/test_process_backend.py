import sys
import unittest
from pathlib import Path

COMPONENT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(COMPONENT_ROOT))

from process_backend import (  # noqa: E402
    ProcessBackendSpec,
    build_process_adapter,
    codex_cli_spec,
    claude_code_cli_spec,
    cursor_cli_spec,
)


class ProcessBackendSpecTests(unittest.TestCase):
    def test_supported_cli_specs_are_explicit_and_not_enabled_by_default(self):
        for factory, agent_id, provider in (
            (codex_cli_spec, "codex", "openai"),
            (claude_code_cli_spec, "claude-code", "anthropic"),
            (cursor_cli_spec, "cursor", "cursor"),
        ):
            with self.subTest(agent_id=agent_id):
                spec = factory("/opt/bin/agent")
                self.assertIsInstance(spec, ProcessBackendSpec)
                self.assertEqual(spec.agent_id, agent_id)
                self.assertEqual(spec.provider, provider)
                self.assertFalse(spec.enabled)
                self.assertTrue(spec.command_template)
                self.assertEqual(spec.capability_map, {"workspace:read": "workspace:read"})

    def test_spec_requires_absolute_executable_and_rejects_shell_or_dynamic_tokens(self):
        with self.assertRaises(ValueError):
            ProcessBackendSpec.from_dict(
                {
                    "schema_version": "northstar.process-backend.v1",
                    "agent_id": "codex",
                    "provider": "openai",
                    "version": "v1",
                    "executable": "codex",
                    "command_template": ["{executable}", "exec", "{prompt}"],
                    "capability_map": {"workspace:read": "workspace:read"},
                    "allowed_env": [],
                    "enabled": False,
                }
            )
        for command in (
            ["/bin/sh", "-c", "unsafe"],
            ["/opt/codex", "{arbitrary}"],
            [],
        ):
            value = {
                "schema_version": "northstar.process-backend.v1",
                "agent_id": "codex",
                "provider": "openai",
                "version": "v1",
                "executable": "/opt/codex",
                "command_template": command,
                "capability_map": {"workspace:read": "workspace:read"},
                "allowed_env": [],
                "enabled": False,
            }
            if command == ["/opt/codex", "{arbitrary}"]:
                value["executable"] = "/bin/sh"
            with self.subTest(command=command):
                with self.assertRaises(ValueError):
                    ProcessBackendSpec.from_dict(value)

    def test_spec_round_trips_and_rejects_unknown_capability_or_environment(self):
        spec = ProcessBackendSpec.from_dict(
            {
                "schema_version": "northstar.process-backend.v1",
                "agent_id": "codex",
                "provider": "openai",
                "version": "v1",
                "executable": "/opt/codex",
                "command_template": ["{executable}", "exec", "--json"],
                "capability_map": {"workspace:read": "workspace:read"},
                "allowed_env": ["LANG"],
                "enabled": False,
            }
        )
        self.assertEqual(spec.to_dict()["executable"], "/opt/codex")
        with self.assertRaises(ValueError):
            ProcessBackendSpec.from_dict({**spec.to_dict(), "unknown": True})
        with self.assertRaises(ValueError):
            ProcessBackendSpec.from_dict({**spec.to_dict(), "capability_map": {"workspace:read": "workspace:write"}})
        with self.assertRaises(ValueError):
            ProcessBackendSpec.from_dict({**spec.to_dict(), "allowed_env": ["API_TOKEN"]})

    def test_disabled_spec_cannot_build_an_adapter_without_explicit_enablement(self):
        spec = codex_cli_spec("/opt/codex")
        with self.assertRaises(ValueError):
            build_process_adapter(
                spec,
                workspace_resolver=lambda workspace_id: "/tmp/private",
                context_loader=lambda context_ref: "context",
            )

    def test_enabled_spec_builds_only_with_explicit_command_and_runtime_bounds(self):
        spec = ProcessBackendSpec.from_dict(
            {
                "schema_version": "northstar.process-backend.v1",
                "agent_id": "codex",
                "provider": "openai",
                "version": "v1",
                "executable": "/opt/codex",
                "command_template": ["{executable}", "exec", "--json"],
                "capability_map": {"workspace:read": "workspace:read"},
                "allowed_env": [],
                "enabled": True,
            }
        )
        adapter = build_process_adapter(
            spec,
            workspace_resolver=lambda workspace_id: "/tmp/private",
            context_loader=lambda context_ref: "context",
            timeout_seconds=10,
            max_output_bytes=1024,
        )
        self.assertEqual(adapter.agent_id, "codex")
        self.assertEqual(adapter.command, ("/opt/codex", "exec", "--json"))


if __name__ == "__main__":
    unittest.main()
