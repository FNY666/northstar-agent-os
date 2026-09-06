import io
import json
import unittest
from contextlib import redirect_stdout
from pathlib import Path

import cli
from loop import RunConfig

from helpers import make_workspace


def write_script(directory: Path, script) -> str:
    path = Path(directory) / "script.json"
    path.write_text(json.dumps(script), encoding="utf-8")
    return str(path)


def run_cli(*argv):
    buffer = io.StringIO()
    with redirect_stdout(buffer):
        code = cli.main(list(argv))
    return code, buffer.getvalue()


class ComputedAllowListTests(unittest.TestCase):
    def test_default_mode_lists_read_tools_only(self):
        allowed = cli.computed_allow_list("default")
        self.assertEqual(allowed, ["Grep", "List", "Read"])

    def test_acceptEdits_adds_edit_tools(self):
        allowed = cli.computed_allow_list("acceptEdits")
        self.assertIn("Write", allowed)
        self.assertIn("Edit", allowed)
        self.assertNotIn("CodexReadOnly", allowed)

    def test_bypass_lists_everything(self):
        allowed = cli.computed_allow_list("bypassPermissions")
        for name in ("Read", "Write", "Edit", "Task", "CodexReadOnly"):
            self.assertIn(name, allowed)


class CliRunTests(unittest.TestCase):
    def test_offline_run_prints_json_events_and_exits_zero(self):
        workspace = make_workspace()
        script = write_script(workspace, [{"text": "reading", "tools": [{"name": "Read", "input": {"path": "nope.txt"}}]}, "done"])
        code, out = run_cli("--prompt", "hi", "--workspace", str(workspace), "--script", script)
        self.assertEqual(code, 0)
        lines = [json.loads(line) for line in out.splitlines()]
        self.assertEqual(lines[0]["type"], "system")
        self.assertEqual(lines[0]["subtype"], "init")
        self.assertEqual(lines[-1]["type"], "result")
        self.assertEqual(lines[-1]["subtype"], "success")
        for line in lines:
            self.assertIn("session_id", line)

    def test_failing_run_exits_one(self):
        workspace = make_workspace()
        script = write_script(workspace, [{"error": "nope"}])
        code, out = run_cli("--prompt", "hi", "--workspace", str(workspace), "--script", script)
        self.assertEqual(code, 1)
        last = json.loads(out.splitlines()[-1])
        self.assertEqual(last["subtype"], "error_during_execution")

    def test_session_file_is_written(self):
        import sessions as sessions_module

        workspace = make_workspace()
        session_file = workspace / "session.jsonl"
        script = write_script(workspace, ["done"])
        code, _ = run_cli("--prompt", "hi", "--workspace", str(workspace), "--script", str(script), "--session", str(session_file))
        self.assertEqual(code, 0)
        records = sessions_module.load_records(session_file)
        self.assertTrue(records)
        self.assertEqual(records[-1]["event"]["type"], "result")

    def test_allow_tool_adds_a_tool(self):
        workspace = make_workspace()
        script = write_script(workspace, [
            {"text": "w", "tools": [{"name": "Write", "input": {"path": "a.txt", "content": "x"}}]},
            "done",
        ])
        code, _ = run_cli(
            "--prompt", "hi", "--workspace", str(workspace), "--script", script,
            "--permission-mode", "default", "--allow-tool", "Write",
        )
        self.assertEqual(code, 0)
        self.assertTrue((workspace / "a.txt").exists())


class DenyToolSubtractionTests(unittest.TestCase):
    """--deny-tool must SUBTRACT from the computed allow list, not coexist with it."""

    def test_deny_tool_in_default_mode_does_not_trip_the_both_lists_guard(self):
        workspace = make_workspace()
        script = write_script(workspace, [
            {"text": "reading", "tools": [{"name": "Read", "input": {"path": "a.txt"}}]},
            "done",
        ])
        # Read is in the default-mode allow list; denying it must not raise.
        code, out = run_cli(
            "--prompt", "hi", "--workspace", str(workspace), "--script", script,
            "--deny-tool", "Read",
        )
        self.assertEqual(code, 0)
        lines = [json.loads(line) for line in out.splitlines()]
        self.assertEqual(lines[-1]["subtype"], "success")
        # the tool call was denied, and the model saw why
        text = out
        self.assertIn("denied", text)
        self.assertIn("disallowed", text)

    def test_deny_tool_in_bypass_mode(self):
        workspace = make_workspace()
        script = write_script(workspace, [
            {"text": "w", "tools": [{"name": "Write", "input": {"path": "a.txt", "content": "x"}}]},
            "done",
        ])
        code, _ = run_cli(
            "--prompt", "hi", "--workspace", str(workspace), "--script", script,
            "--permission-mode", "bypassPermissions", "--deny-tool", "Write",
        )
        self.assertEqual(code, 0)
        self.assertFalse((workspace / "a.txt").exists())

    def test_deny_tool_combined_with_allow_tool_stays_disjoint(self):
        workspace = make_workspace()
        script = write_script(workspace, [
            {"text": "w", "tools": [{"name": "Write", "input": {"path": "a.txt", "content": "x"}}]},
            "done",
        ])
        code, _ = run_cli(
            "--prompt", "hi", "--workspace", str(workspace), "--script", script,
            "--permission-mode", "default", "--allow-tool", "Write", "--deny-tool", "Write",
        )
        self.assertEqual(code, 0)
        self.assertFalse((workspace / "a.txt").exists())

    def test_programmatic_overlap_still_raises_the_guard(self):
        workspace = make_workspace()
        from loop import AgentRuntime
        from providers.scripted import ScriptedProvider

        with self.assertRaises(ValueError):
            AgentRuntime(
                ScriptedProvider(["done"]),
                RunConfig(workspace=workspace, allowed_tools=("Read",), disallowed_tools=("Read",)),
            )


if __name__ == "__main__":
    unittest.main()
