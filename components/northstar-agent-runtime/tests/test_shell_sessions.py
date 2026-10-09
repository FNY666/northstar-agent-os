"""Shell sessions: cwd and env persist across calls within a named session.

This is the programming-priority work: a multi-step flow (cd into a project,
export vars, build, test) keeps context instead of re-establishing it every
call. Sessions are scoped to the run via ctx.session_id — they never cross
runs, and they grant no new privilege (cwd is re-resolved every call, env
still passes the sandbox's protected-var filter).
"""
from __future__ import annotations

import re
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
        c = str(ev.content)
        # c is str() of a repr'd block: tool_use_id=\'t1\', content="...\\n--- stdout ---\\nhi\"..."
        for m in re.finditer(r"tool_use_id='(\w+)'", c):
            tid = m.group(1)
            seg = c[m.start():m.start() + 4000]
            sm = re.search(r"--- stdout ---(.*?)\", is_error", seg, re.S)
            if sm:
                out[tid] = sm.group(1).replace("\\n", "\n").strip()
            elif "(no output)" in seg:
                out[tid] = ""
    return out


class ShellSessionTests(RuntimeTestCase):
    def _drive(self, turns):
        def approve(tool, args, context):
            return True
        rt = self.runtime(turns, can_use_tool=approve, allowed_tools=["Shell"])
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
