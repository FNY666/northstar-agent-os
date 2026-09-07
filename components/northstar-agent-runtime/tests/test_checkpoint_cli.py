"""CLI contracts for checkpoint inspection and reversible operations."""
from __future__ import annotations

import contextlib
import io
import json
import shutil
import tempfile
import unittest
from pathlib import Path

import support  # noqa: F401
from cli import main


def run_cli(*argv: str) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(list(argv))
    return code, out.getvalue(), err.getvalue()


class CheckpointCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="northstar-checkpoint-cli-"))
        self.workspace = self.tmp / "workspace"
        self.workspace.mkdir()
        (self.workspace / "a.txt").write_text("before\n", encoding="utf-8")
        self.sessions = self.tmp / "sessions"
        self.session_id = "ns-cli-checkpoint"

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def checkpoint(self) -> str:
        code, output, error = run_cli(
            "sessions", "checkpoint", "--session-dir", str(self.sessions),
            "--workspace", str(self.workspace), "--json", self.session_id,
        )
        self.assertEqual(code, 0, error)
        return json.loads(output)["checkpoint_id"]

    def test_checkpoint_inspect_diff_and_rewind_are_scriptable(self):
        checkpoint_id = self.checkpoint()
        code, output, error = run_cli(
            "sessions", "inspect", "--session-dir", str(self.sessions), "--json", self.session_id,
        )
        self.assertEqual(code, 0, error)
        self.assertEqual(json.loads(output.splitlines()[0])["checkpoint_id"], checkpoint_id)
        (self.workspace / "a.txt").write_text("after\n", encoding="utf-8")
        code, output, error = run_cli(
            "sessions", "diff", "--session-dir", str(self.sessions), "--workspace", str(self.workspace),
            "--json", self.session_id, checkpoint_id,
        )
        self.assertEqual(code, 0, error)
        self.assertEqual(json.loads(output)["changes"][0]["status"], "modified")
        code, _output, error = run_cli(
            "sessions", "rewind", "--session-dir", str(self.sessions), "--workspace", str(self.workspace),
            self.session_id, checkpoint_id,
        )
        self.assertEqual(code, 1)
        self.assertIn("force", error)
        code, output, error = run_cli(
            "sessions", "rewind", "--session-dir", str(self.sessions), "--workspace", str(self.workspace),
            "--force", "--json", self.session_id, checkpoint_id,
        )
        self.assertEqual(code, 0, error)
        self.assertIsNotNone(json.loads(output)["safety_checkpoint_id"])
        self.assertEqual((self.workspace / "a.txt").read_text(encoding="utf-8"), "before\n")

    def test_fork_command_creates_a_child_workspace(self):
        checkpoint_id = self.checkpoint()
        child = self.tmp / "child"
        code, output, error = run_cli(
            "sessions", "fork", "--session-dir", str(self.sessions), "--workspace", str(child),
            "--new-session-id", "ns-child", "--json", self.session_id, checkpoint_id,
        )
        self.assertEqual(code, 0, error)
        report = json.loads(output)
        self.assertEqual(report["source_checkpoint_id"], checkpoint_id)
        self.assertEqual((child / "a.txt").read_text(encoding="utf-8"), "before\n")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
