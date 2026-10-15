"""Shell sessions: cwd and env persist across calls within a named session.

This is the programming-priority work: a multi-step flow (cd into a project,
export vars, build, test) keeps context instead of re-establishing it every
call. Session state belongs to one run's ToolContext, not its transcript
session_id, and grants no new privilege (cwd is re-resolved every call, env
still passes the sandbox's protected-var filter).
"""
from __future__ import annotations

import sys

sys.path.insert(0, ".")
sys.path.insert(0, "tests")

from support import RuntimeTestCase
from providers.base import TextBlock, ToolUseBlock, UserMessage
from providers.scripted import ScriptedTurn


def _stdouts(report):
    """Map tool_use_id -> stdout text ('' when the call produced no output)."""
    out = {}
    for ev in report.events:
        if not isinstance(ev, UserMessage):
            continue
        for block in ev.tool_results:
            content = block.text()
            stdout_marker = "--- stdout ---\n"
            stderr_marker = "\n--- stderr ---"
            if stdout_marker in content:
                stdout = content.split(stdout_marker, 1)[1]
                if stderr_marker in stdout:
                    stdout = stdout.split(stderr_marker, 1)[0]
                out[block.tool_use_id] = stdout.strip()
            else:
                out[block.tool_use_id] = ""
    return out


class ShellSessionTests(RuntimeTestCase):
    def _drive(self, turns):
        def approve(tool, args, context):
            return True
        # These tests exercise cwd/env lifecycle, not kernel isolation. Use the
        # portable process backend without optional kernel hardening so they
        # also run on hosts whose kernels lack Landlock/seccomp support.
        rt = self.runtime(
            turns,
            can_use_tool=approve,
            allowed_tools=["Shell"],
            shell_backend="process",
            shell_seccomp="off",
            shell_capdrop="off",
            shell_landlock="off",
        )
        return self.drive(rt)

    def _turn(self, tid, tool_input, text="x"):
        return ScriptedTurn(blocks=(
            ToolUseBlock(id=tid, name="Shell", input=tool_input),
            TextBlock(text=text),
        ), stop_reason="tool_use")

    def test_session_remembers_cwd(self):
        """cwd= once in a session; later session calls stay there."""
        report = self._drive([
            self._turn("t0", {"command": "mkdir -p proj"}),
            self._turn("t1", {"command": "pwd", "cwd": "proj", "session": "s1"}),
            self._turn("t2", {"command": "pwd", "session": "s1"}),
        ])
        self.assertEqual(len(report.denials), 0)
        stdouts = _stdouts(report)
        self.assertTrue(stdouts["t1"].rstrip().endswith("/proj"),
                        f"t1 pwd not in proj: {stdouts['t1'][:60]}")
        self.assertTrue(stdouts["t2"].rstrip().endswith("/proj"),
                        f"session did not remember cwd: {stdouts['t2'][:60]}")

    def test_session_remembers_env(self):
        """env= once in a session; later session calls see it."""
        report = self._drive([
            self._turn("t1", {"command": "echo SET",
                              "env": {"MYVAR": "hello123"}, "session": "s2"}),
            self._turn("t2", {"command": "echo VAR=$MYVAR", "session": "s2"}),
        ])
        self.assertEqual(len(report.denials), 0)
        stdouts = _stdouts(report)
        self.assertIn("VAR=hello123", stdouts["t2"],
                      f"session did not remember env: {stdouts['t2'][:60]}")

    def test_sessions_are_isolated(self):
        """Different session names do not share cwd/env."""
        report = self._drive([
            self._turn("t0", {"command": "mkdir -p other"}),
            self._turn("t1", {"command": "echo ok", "cwd": "other",
                              "env": {"MYVAR": "zzz"}, "session": "s3"}),
            self._turn("t2", {"command": "pwd && echo VAR=$MYVAR",
                              "session": "s4"}),
        ])
        stdouts = _stdouts(report)
        self.assertNotIn("/other", stdouts["t2"])
        self.assertIn("VAR=", stdouts["t2"])
        self.assertNotIn("zzz", stdouts["t2"])

    def test_no_session_no_persistence(self):
        """Without session=, behavior is unchanged: no state carries over."""
        report = self._drive([
            self._turn("t0", {"command": "mkdir -p nosess"}),
            self._turn("t1", {"command": "echo ok", "cwd": "nosess"}),
            self._turn("t2", {"command": "pwd"}),
        ])
        stdouts = _stdouts(report)
        self.assertNotIn("/nosess", stdouts["t2"],
                         "cwd leaked across calls without a session")

    def test_explicit_cwd_updates_session(self):
        """A per-call cwd overrides and updates the remembered session cwd."""
        report = self._drive([
            self._turn("t0", {"command": "mkdir -p da db"}),
            self._turn("t1", {"command": "pwd", "cwd": "da", "session": "s5"}),
            self._turn("t2", {"command": "pwd", "cwd": "db", "session": "s5"}),
            self._turn("t3", {"command": "pwd", "session": "s5"}),
        ])
        stdouts = _stdouts(report)
        self.assertTrue(stdouts["t1"].rstrip().endswith("/da"))
        self.assertTrue(stdouts["t2"].rstrip().endswith("/db"))
        self.assertTrue(stdouts["t3"].rstrip().endswith("/db"),
                        f"session did not adopt explicit cwd: {stdouts['t3'][:60]}")

    def test_per_call_env_overrides_session_env(self):
        """Per-call env wins on conflict and updates the session."""
        report = self._drive([
            self._turn("t1", {"command": "echo A=$A",
                              "env": {"A": "one"}, "session": "s6"}),
            self._turn("t2", {"command": "echo A=$A",
                              "env": {"A": "two"}, "session": "s6"}),
            self._turn("t3", {"command": "echo A=$A", "session": "s6"}),
        ])
        stdouts = _stdouts(report)
        self.assertIn("A=one", stdouts["t1"])
        self.assertIn("A=two", stdouts["t2"])
        self.assertIn("A=two", stdouts["t3"],
                      f"session did not adopt per-call env: {stdouts['t3'][:60]}")

    def test_named_session_state_does_not_cross_runs_with_reused_session_id(self):
        """A later run starts clean even when the host reuses a transcript id."""
        workspace = self.workspace()
        (workspace / "previous-run").mkdir()

        def approve(tool, args, context):
            return True

        runtime = self.runtime(
            [
                self._turn(
                    "t1",
                    {
                        "command": "pwd && (env | grep '^VALUE=' || echo VALUE=unset)",
                        "cwd": "previous-run",
                        "env": {"VALUE": "first-run"},
                        "session": "build",
                    },
                ),
                ScriptedTurn(blocks=(TextBlock(text="first run done"),), stop_reason="end_turn"),
                self._turn(
                    "t2",
                    {
                        "command": "pwd && (env | grep '^VALUE=' || echo VALUE=unset)",
                        "session": "build",
                    },
                ),
                ScriptedTurn(blocks=(TextBlock(text="second run done"),), stop_reason="end_turn"),
            ],
            workspace=workspace,
            can_use_tool=approve,
            allowed_tools=["Shell"],
            shell_backend="process",
            shell_seccomp="off",
            shell_capdrop="off",
            shell_landlock="off",
            session_id="reused-transcript-id",
        )

        first = runtime.run_collect("first run")
        second = runtime.run_collect("second run")

        self.assertTrue(first.ok, first.errors)
        self.assertTrue(second.ok, second.errors)
        self.assertEqual(first.session_id, "reused-transcript-id")
        self.assertEqual(second.session_id, first.session_id)
        first_output = _stdouts(first)["t1"]
        second_output = _stdouts(second)["t2"]
        self.assertTrue(first_output.splitlines()[0].endswith("/previous-run"), first_output)
        self.assertIn("VALUE=first-run", first_output)
        self.assertFalse(second_output.splitlines()[0].endswith("/previous-run"), second_output)
        self.assertIn("VALUE=unset", second_output)
