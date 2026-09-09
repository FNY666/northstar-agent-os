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
from mcp_client import (
    MCP_BASE_ENV_KEYS,
    McpError,
    McpStdioClient,
    argv_digest,
    mcp_environment,
    mcp_tool_specs,
    parse_mcp_flag,
)

SECRET_SENTINEL = "ghp_sentinel-value-never-for-the-child"

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "mcp_echo_server.py"
MRTR_FIXTURE = Path(__file__).resolve().parent / "fixtures" / "mcp_mrtr_server.py"
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
        # The server is made unresponsive by handing it MCP_SILENT through the same door a real
        # server gets its configuration: the client's env map. A child no longer picks a
        # variable up by finding it in the test process, which is the point of the rule.
        client = McpStdioClient(
            "demo", ["python3", str(FIXTURE)], timeout_ms=FAST_TIMEOUT_MS, env={"MCP_SILENT": "1"}
        )
        with self.assertRaises(McpError) as caught:
            client.connect()
        self.assertIn("timed out", str(caught.exception))
        self.assertIsNone(client._proc, "the timed-out server must be closed")

    def test_a_slow_call_times_out_and_reports_an_error_result(self):
        client = McpStdioClient(
            "demo", ["python3", str(FIXTURE)], timeout_ms=FAST_TIMEOUT_MS, env={"MCP_SLOW_TOOL": "1"}
        )
        client.connect()
        result = client.call_tool("echo", {"text": "x"})
        self.assertTrue(result.is_error)
        self.assertIn("timed out", result.text())
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


class GenerationFlagTests(unittest.TestCase):
    """The generation and elicitation flags, as the operator meets them."""

    def setUp(self):
        self.ws = Path(tempfile.mkdtemp(prefix="nsar-mcpgen-"))
        self.saved_env = dict(os.environ)
        # Set in the environment *and* named in run_with's --mcp-env, which is the operator's
        # workflow for a server that needs a variable: this class exercises the CLI path of it.
        os.environ["MRTR_SERVER_MODE"] = "discover"

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self.saved_env)

    def server(self) -> str:
        return f"demo=python3 {MRTR_FIXTURE}"

    def script(self, tool_name: str, tool_input: dict[str, object] | None = None) -> Path:
        path = self.ws / "s.json"
        path.write_text(
            json.dumps([{"tool": {"name": tool_name, "input": tool_input or {}, "id": "g1"}}, {"text": "done"}]),
            encoding="utf-8",
        )
        return path

    def run_with(self, *extra: str) -> tuple[int, str, str]:
        script = self.script("mcp__demo__needs_input")
        return run_cli(
            "run",
            "--workspace",
            str(self.ws),
            "--prompt",
            "call",
            "--script",
            str(script),
            "--mcp-server",
            self.server(),
            "--allow-tool",
            "mcp__demo__needs_input",
            "--mcp-allow-exec",
            "--mcp-env",
            "MRTR_SERVER_MODE",
            *extra,
        )

    def test_the_stance_is_printed_even_in_a_dry_run(self):
        code, out, _ = run_cli(
            "run", "--workspace", str(self.ws), "--prompt", "hi", "--scripted-text", "x",
            "--mcp-server", self.server(), "--dry-run",
        )
        self.assertEqual(code, 0)
        self.assertIn("protocol=auto, elicit=off", out)
        self.assertIn("roots=off, sensitive_input=off, rounds=3", out)

    def test_unattended_a_remote_question_becomes_a_visible_tool_error(self):
        code, out, _ = self.run_with("--json")
        self.assertEqual(code, 0)
        self.assertIn("declined without calling the tool", out)
        self.assertIn("no approver attached", out)

    def test_pre_approved_answers_let_the_call_through(self):
        code, out, _ = self.run_with(
            "--json", "--mcp-elicit", "--mcp-elicit-answers", json.dumps({"approved": True}), "--quiet"
        )
        self.assertEqual(code, 0, out)
        self.assertIn("answered after 1 ask(s)", out)
        self.assertIn('"action": "accept"', out.replace("\\", ""))

    def test_eliciting_without_a_terminal_is_a_configuration_error(self):
        code, _, err = self.run_with("--mcp-elicit")
        self.assertEqual(code, USAGE_ERROR)
        self.assertIn("needs a terminal or --mcp-elicit-answers", err)

    def test_malformed_pre_approved_answers_are_rejected_before_any_spawn(self):
        code, _, err = self.run_with("--mcp-elicit", "--mcp-elicit-answers", "{oops")
        self.assertEqual(code, 64)
        self.assertIn("not valid JSON", err)
        code, _, err = self.run_with("--mcp-elicit", "--mcp-elicit-answers", "[1,2]")
        self.assertEqual(code, 64)
        self.assertIn("must be a JSON object", err)

    def test_the_round_cap_is_validated_as_configuration(self):
        code, _, err = self.run_with("--mcp-max-rounds", "0")
        self.assertEqual(code, 64)
        self.assertIn("between 1 and 8", err)

    def test_a_pinned_legacy_generation_still_reaches_the_modern_only_server_error(self):
        # The operator said "legacy"; the client obeys and reports what the server said
        # instead of quietly trying something else.
        code, _, err = self.run_with("--mcp-protocol", "legacy")
        self.assertEqual(code, 64)
        self.assertIn("modern-only", err)

    def test_the_probe_result_reaches_the_log(self):
        code, _, err = self.run_with()
        self.assertEqual(code, 0, err)
        self.assertIn("server/discover answered: modern server", err)

    def test_the_older_server_is_unaffected_by_the_new_flags(self):
        code, out, _ = run_cli(
            "run",
            "--workspace",
            str(self.ws),
            "--prompt",
            "call",
            "--script",
            str(self.script("mcp__demo__echo", {"text": "still fine"})),
            "--mcp-server",
            f"demo=python3 {FIXTURE}",
            "--allow-tool",
            "mcp__demo__echo",
            "--mcp-protocol",
            "auto",
            "--json",
        )
        self.assertEqual(code, 0, out)
        self.assertIn("echo:still fine", out)


class ServerChildEnvironmentTests(unittest.TestCase):
    """What a server process can read about the machine that started it (finding F5).

    Before this rule, a repository file naming a command bought the whole parent environment:
    the provider's API key, cloud tokens, whatever the operator keeps there. The sandboxed Shell
    tool scrubs its child and command hooks receive three variables; an MCP server was the one
    place in the house where a repo-authored process was handed everything, and nothing in the
    file's shape announced the difference.
    """

    def test_server_child_inherits_no_credentials(self):
        # Asserted in the child, not about the dict the parent built: the fixture writes the
        # MCP_TEST_* variables it was actually given, so a value that leaked through any
        # inherited path - including one nobody thought to filter - would show up here.
        marker = Path(tempfile.mkdtemp(prefix="nsar-mcpenv-")) / "seen.json"
        os.environ["MCP_TEST_PARENT_SECRET"] = SECRET_SENTINEL
        self.addCleanup(os.environ.pop, "MCP_TEST_PARENT_SECRET", None)
        client = McpStdioClient(
            "demo",
            ["python3", str(FIXTURE)],
            timeout_ms=FAST_TIMEOUT_MS,
            env={"MCP_SPAWN_REPORT": str(marker), "MCP_TEST_FROM_FILE": "declared"},
        )
        try:
            client.connect()
        finally:
            client.close()
        seen = json.loads(marker.read_text(encoding="utf-8"))
        self.assertEqual(
            seen["env"],
            {"MCP_TEST_FROM_FILE": "declared"},
            "the parent's MCP_TEST_PARENT_SECRET reached the server child",
        )

    def test_only_named_variables_are_inherited(self):
        parent = {
            "PATH": "/usr/bin",
            "LANG": "C.UTF-8",
            "HOME": "/home/operator",
            "AWS_SECRET_ACCESS_KEY": "leak-me",
            "ANTHROPIC_API_KEY": "leak-me-too",
            "GIT_TOKEN": "release-me",
        }
        env = mcp_environment(
            declared={"SERVER_MODE": "read-only"}, inherit=("GIT_TOKEN", "ABSENT_NAME"), environment=parent
        )
        self.assertEqual(
            env,
            {
                "PATH": "/usr/bin",
                "LANG": "C.UTF-8",
                "GIT_TOKEN": "release-me",
                "SERVER_MODE": "read-only",
                "NORTHSTAR_MCP": "1",
            },
        )
        self.assertNotIn("HOME", env, "a name nobody released is not handed over because a server asked")

    def test_the_base_environment_is_no_wider_than_a_sandboxed_commands(self):
        # The invariant, stated as a subset rather than as a file hash: the child an MCP server
        # gets may never see a variable the same runtime would strip from a sandboxed `Shell`
        # call. Two lists of "what a child may inherit" drift; one shared rule does not.
        from tools.os_sandbox import _scrubbed_env

        sandbox = set(_scrubbed_env({}, workspace=Path(tempfile.mkdtemp(prefix="nsar-mcpbase-"))))
        extra = set(MCP_BASE_ENV_KEYS) - sandbox
        self.assertFalse(extra, f"an MCP child inherits {sorted(extra)}, which a sandboxed command would be stripped of")

    def test_launch_summary_fingerprints_argv_instead_of_printing_it(self):
        secret_path = "/srv/run/secrets/TOKEN=leak-me"
        client = McpStdioClient("demo", ["python3", secret_path], timeout_ms=FAST_TIMEOUT_MS)
        summary = client.launch_summary()
        self.assertEqual(summary["argv_entries"], 2)
        self.assertNotIn("leak-me", json.dumps(summary))
        self.assertEqual(summary["argv_digest"], argv_digest(["python3", secret_path]))
        self.assertEqual(len(summary["argv_digest"]), 16)
        self.assertNotEqual(argv_digest(["python3", secret_path]), argv_digest(["python3", "other.py"]))

    def test_a_server_with_no_declared_cwd_starts_in_the_workspace(self):
        # `cwd` absent used to mean "wherever the CLI happened to be invoked", which is not the
        # directory the run is governing, and the same value is what roots/list announces.
        root = Path(tempfile.mkdtemp(prefix="nsar-mcpcwd-"))
        client = McpStdioClient(
            "demo", ["python3", "x.py"], timeout_ms=FAST_TIMEOUT_MS, workspace_root=str(root), allow_roots=True
        )
        self.assertEqual(client.cwd, str(root))
        self.assertEqual(client.launch_summary()["cwd_relative"], ".")
        self.assertEqual(client.launch_summary()["roots"], "workspace")


if __name__ == "__main__":
    unittest.main()
