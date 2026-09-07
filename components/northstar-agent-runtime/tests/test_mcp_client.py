"""Minimal MCP stdio client: handshake, tool listing, calls, timeouts, cleanup,
and the governed path through the CLI (mutating-by-default + permission gate).
"""
from __future__ import annotations

import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import mcp_client
from cli import USAGE_ERROR, main
from mcp_client import McpError, McpStdioClient, mcp_tool_specs, parse_mcp_flag

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "mcp_echo_server.py"
FAST_TIMEOUT_MS = 500


def run_cli(*argv: str) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    saved_stdin, sys.stdin = sys.stdin, io.StringIO("")
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(list(argv))
    finally:
        sys.stdin = saved_stdin
    return code, out.getvalue(), err.getvalue()


class ParseFlagTests(unittest.TestCase):
    def test_flag_is_split_on_the_first_equals(self):
        name, command = parse_mcp_flag("demo=python3 server.py --port 9")
        self.assertEqual(name, "demo")
        self.assertEqual(command, ["python3", "server.py", "--port", "9"])

    def test_missing_equals_or_empty_name_or_command_is_an_error(self):
        for bad in ("demo", "=ls", "Bad=ls", "demo=", "demo= "):
            with self.assertRaises(ValueError):
                parse_mcp_flag(bad)


class ClientTests(unittest.TestCase):
    def connect(self, *, env: dict[str, str] | None = None, timeout_ms: int = 4000) -> McpStdioClient:
        client = McpStdioClient("demo", ["python3", str(FIXTURE)], timeout_ms=timeout_ms)
        saved = dict(os.environ)
        if env:
            os.environ.update(env)
        try:
            client.connect()
        finally:
            os.environ.clear()
            os.environ.update(saved)
        return client

    def test_handshake_lists_tools_with_governed_names(self):
        client = self.connect()
        try:
            self.assertEqual(client.tool_names(), ("echo", "fail"))
            specs = mcp_tool_specs(client)
            self.assertEqual([spec.name for spec in specs], ["mcp__demo__echo", "mcp__demo__fail"])
            echo = specs[0]
            self.assertTrue(echo.is_mutating, "remote tools are mutating by default")
            self.assertFalse(echo.needs_workspace)
            self.assertEqual(echo.kind, "other")
        finally:
            client.close()

    def test_call_echo_returns_the_text(self):
        client = self.connect()
        try:
            spec = mcp_tool_specs(client)[0]
            result = spec.handler({"text": "hello mcp"}, None)
            self.assertFalse(result.is_error)
            self.assertEqual(result.text(), "echo:hello mcp")
        finally:
            client.close()

    def test_call_failing_tool_reports_is_error(self):
        client = self.connect()
        try:
            specs = {spec.name: spec for spec in mcp_tool_specs(client)}
            result = specs["mcp__demo__fail"].handler({}, None)
            self.assertTrue(result.is_error)
            self.assertIn("boom", result.text())
        finally:
            client.close()

    def test_unknown_tool_inside_a_known_server_is_an_error_result(self):
        client = self.connect()
        try:
            result = client.call_tool("echo", {"text": "x"})  # fine
            self.assertFalse(result.is_error)
            result = client.call_tool("nope", {})
            self.assertTrue(result.is_error)
            self.assertIn("nope", result.text())
        finally:
            client.close()

    def test_missing_server_command_is_an_operator_error(self):
        client = McpStdioClient("demo", ["definitely-not-a-real-binary-xyz"], timeout_ms=1000)
        with self.assertRaises(McpError) as caught:
            client.connect()
        self.assertIn("cannot start", str(caught.exception))

    def test_a_server_that_never_answers_is_killed_on_timeout(self):
        client = McpStdioClient("demo", ["python3", str(FIXTURE)], timeout_ms=FAST_TIMEOUT_MS)
        saved = dict(os.environ)
        os.environ["MCP_SILENT"] = "1"
        try:
            with self.assertRaises(McpError) as caught:
                client.connect()
            self.assertIn("timed out", str(caught.exception))
            self.assertIsNone(client._proc, "the timed-out server must be closed")
        finally:
            os.environ.clear()
            os.environ.update(saved)

    def test_a_slow_call_times_out_and_reports_an_error_result(self):
        client = McpStdioClient("demo", ["python3", str(FIXTURE)], timeout_ms=FAST_TIMEOUT_MS)
        saved = dict(os.environ)
        os.environ["MCP_SLOW_TOOL"] = "1"
        try:
            client.connect()
            result = client.call_tool("echo", {"text": "x"})
            self.assertTrue(result.is_error)
            self.assertIn("timed out", result.text())
        finally:
            os.environ.clear()
            os.environ.update(saved)
            client.close()

    def test_close_terminates_the_server_process_group(self):
        client = self.connect()
        proc = client._proc
        self.assertIsNotNone(proc)
        assert proc is not None and proc.pid is not None
        client.close()
        with self.assertRaises(ProcessLookupError):
            os.kill(proc.pid, 0)  # no such process anymore
        self.assertIsNone(client._proc)
        client.close()  # idempotent


class CliIntegrationTests(unittest.TestCase):
    """MCP tools cross the CLI's permission gate exactly like local tools."""

    def setUp(self):
        self.ws = Path(tempfile.mkdtemp(prefix="nsar-mcpcli-"))
        (self.ws / "f.txt").write_text("hello\n", encoding="utf-8")

    def server_flag(self) -> str:
        return f"demo=python3 {FIXTURE}"

    def script(self, tool_name: str, tool_input: dict[str, object]) -> Path:
        path = self.ws / "s.json"
        path.write_text(
            json.dumps([{"tool": {"name": tool_name, "input": tool_input, "id": "m1"}}, {"text": "done"}]),
            encoding="utf-8",
        )
        return path

    def test_dry_run_lists_servers_without_connecting(self):
        code, out, _ = run_cli("run", "--workspace", str(self.ws), "--prompt", "hi",
                               "--scripted-text", "x", "--mcp-server", self.server_flag(), "--dry-run")
        self.assertEqual(code, 0)
        self.assertIn("mcp_servers=demo=python3", out)
        self.assertIn("not connected in dry-run", out)

    def test_an_allowed_mcp_call_succeeds(self):
        script = self.script("mcp__demo__echo", {"text": "hello mcp"})
        code, out, err = run_cli("run", "--workspace", str(self.ws), "--prompt", "call", "--script", str(script),
                                 "--mcp-server", self.server_flag(), "--allow-tool", "mcp__demo__echo", "--json")
        self.assertEqual(code, 0, err)
        self.assertIn("echo:hello mcp", out)
        self.assertIn('"subtype": "success"', out)

    def test_a_denied_mcp_call_hits_the_gate_and_halt_exits_5(self):
        script = self.script("mcp__demo__echo", {"text": "x"})
        code, _, _ = run_cli("run", "--workspace", str(self.ws), "--prompt", "call", "--script", str(script),
                             "--mcp-server", self.server_flag(), "--halt-on-denial", "--quiet")
        self.assertEqual(code, 5)

    def test_a_failing_mcp_tool_reaches_the_events_stream_as_error(self):
        script = self.script("mcp__demo__fail", {})
        code, out, _ = run_cli("run", "--workspace", str(self.ws), "--prompt", "call", "--script", str(script),
                               "--mcp-server", self.server_flag(), "--allow-tool", "mcp__demo__fail", "--json")
        self.assertEqual(code, 0)
        self.assertIn("boom", out)

    def test_mcp_plus_an_agent_definition_is_a_configuration_error(self):
        code, _, err = run_cli("run", "--workspace", str(self.ws), "--prompt", "hi",
                               "--scripted-text", "x", "--mcp-server", self.server_flag(), "--agent", "explorer")
        self.assertEqual(code, USAGE_ERROR)
        self.assertIn("cannot be combined", err)

    def test_unreachable_mcp_server_is_a_configuration_error(self):
        code, _, err = run_cli("run", "--workspace", str(self.ws), "--prompt", "hi",
                               "--scripted-text", "x",
                               "--mcp-server", "demo=definitely-not-a-real-binary-xyz")
        self.assertEqual(code, USAGE_ERROR)
        self.assertIn("cannot start", err)

    def test_a_policy_file_can_deny_an_mcp_tool_by_name(self):
        (self.ws / ".northstar").mkdir(exist_ok=True)
        (self.ws / ".northstar" / "config.toml").write_text(
            'deny_tools = ["mcp__demo__echo"]\nhalt_on_denial = true\n', encoding="utf-8"
        )
        script = self.script("mcp__demo__echo", {"text": "x"})
        code, _, _ = run_cli("run", "--workspace", str(self.ws), "--prompt", "call", "--script", str(script),
                             "--mcp-server", self.server_flag())
        self.assertEqual(code, 5, "a policy-denied mcp tool must stay denied even with no --allow-tool")

    def test_no_mcp_servers_leaves_the_registry_clean(self):
        code, out, _ = run_cli("tools")
        self.assertEqual(code, 0)
        self.assertNotIn("mcp__", out)


if __name__ == "__main__":
    unittest.main()
