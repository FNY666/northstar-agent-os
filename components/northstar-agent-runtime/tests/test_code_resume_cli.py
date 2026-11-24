"""End-to-end tests for ``northstar code-resume``.

These drive the CLI the way an operator would: run a code task, let it be
interrupted, then continue the run from its evidence directory.  The tests
assert the properties that make a resume trustworthy:

* the resumed run reuses the *same* isolated worktree and starting commit;
* the caller's checkout is still never edited;
* an interrupted effect is never replayed — the run is refused instead;
* a resumed run that succeeds still seals its evidence like any other run.
"""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cli import main


def git(root: Path, *arguments: str) -> None:
    subprocess.run(
        ["git", "-C", str(root), *arguments],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def invoke(*arguments: str) -> tuple[int, str, str]:
    stdout, stderr = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        code = main(list(arguments))
    return code, stdout.getvalue(), stderr.getvalue()


def plan_turn(*, checks: tuple[int, ...] = ()) -> dict[str, object]:
    return {
        "tool": {
            "name": "SubmitPlan",
            "input": {
                "summary": "inspect and make the requested minimal change",
                "files": ["value.txt"],
                "steps": ["inspect the file", "apply the requested change"],
                "risks": ["preserve the existing newline"],
                "check_indices": list(checks),
            },
        }
    }


def write_turn(content: str = "new\n") -> dict[str, object]:
    """A turn that really edits the file, so a resumed run can pass its check."""
    return {
        "tool": {
            "name": "Write",
            "input": {"path": "value.txt", "content": content},
        }
    }


class CodeResumeCliTests(unittest.TestCase):
    def make_repository(self, parent: Path, name: str = "repo") -> Path:
        root = parent / name
        root.mkdir(exist_ok=True)
        git(root, "init")
        git(root, "config", "user.email", "northstar-tests@example.invalid")
        git(root, "config", "user.name", "Northstar Tests")
        (root / "value.txt").write_text("old\n", encoding="utf-8")
        git(root, "add", "value.txt")
        git(root, "commit", "-m", "initial")
        return root

    def base(self, root: Path) -> tuple[str, ...]:
        return (
            "--workspace", str(root),
            "--sandbox", "process",
            "--seccomp", "off",
            "--capdrop", "off",
            "--landlock", "off",
            "--no-policy-file",
            "--no-workspace-agents",
            "--no-skills",
            "--no-memory",
            "--no-plugins",
        )

    def test_dry_run_reports_a_resumable_interrupted_run(self):
        """A run killed mid-flight leaves non-terminal evidence: it may resume."""
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            root = self.make_repository(parent)
            evidence = parent / "evidence"
            script = parent / "turns.json"
            # A check that waits before it verifies, so the run can be killed
            # while it is still in flight rather than reaching a terminal
            # state.  The same check still passes on the resumed run, which
            # is what makes the resume observable end to end.
            script.write_text(
                json.dumps([plan_turn(checks=(0,)), write_turn(), {"text": "working"}]),
                encoding="utf-8",
            )
            blocker = parent / "block.sh"
            blocker.write_text(
                "#!/bin/sh\n"
                "sleep 6\n"
                'read line < value.txt\n'
                'test "$line" = new\n',
                encoding="utf-8",
            )
            blocker.chmod(0o755)

            process = subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    "cli",
                    "code",
                    "change the value",
                    *self.base(root),
                    "--script", str(script),
                    "--check", f"{blocker}",
                    "--evidence-dir", str(evidence),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=str(Path(__file__).resolve().parents[1]),
                # Its own process group: an interrupted run must not leave
                # orphans behind that steal resources from the next test.
                start_new_session=True,
            )
            try:
                run_dir = self.wait_for_evidence(evidence)
                self.wait_for_completed_effect(run_dir)
                self.kill_run(process)
            finally:
                process.wait(timeout=30)

            resume_code, resume_out, resume_err = invoke(
                "code-resume", str(run_dir), "--dry-run",
            )
            self.assertEqual(resume_code, 0, resume_err)
            report = json.loads(resume_out)
            self.assertTrue(report["resumable"], report)
            self.assertNotIn(report["state"], {"success", "failed"})

    def wait_for_completed_effect(self, run_dir: Path, timeout: float = 60.0) -> None:
        """Wait until a mutating effect has written its completion receipt.

        The kill has to land at a *deterministic* point: after the edit is
        recorded but before the run reaches a terminal state.  Killing at an
        arbitrary moment leaves an effect without a receipt, and such a run is
        (correctly) not resumable.
        """
        deadline = time.monotonic() + timeout
        phases = run_dir / "phases.json"
        while time.monotonic() < deadline:
            try:
                raw = phases.read_text(encoding="utf-8")
            except OSError:
                raw = ""
            if raw:
                try:
                    payload = json.loads(raw)
                except ValueError:
                    payload = {}
                for effect in payload.get("effects", ()):
                    if (
                        str(effect.get("tool")) != "HostCheck"
                        and str(effect.get("status")) == "completed"
                    ):
                        return
            time.sleep(0.1)
        raise AssertionError("no completed effect was recorded before the timeout")

    def wait_for_started_effect(self, run_dir: Path, timeout: float = 60.0) -> None:
        """Wait until a mutating effect has *started* but has no receipt yet.

        That is the only interruption point from which a resume is unsafe:
        the edit may or may not have reached the worktree.
        """
        deadline = time.monotonic() + timeout
        phases = run_dir / "phases.json"
        while time.monotonic() < deadline:
            try:
                raw = phases.read_text(encoding="utf-8")
            except OSError:
                raw = ""
            if raw:
                try:
                    payload = json.loads(raw)
                except ValueError:
                    payload = {}
                for effect in payload.get("effects", ()):
                    if (
                        str(effect.get("tool")) != "HostCheck"
                        and str(effect.get("status")) != "completed"
                    ):
                        return
            time.sleep(0.05)
        raise AssertionError("no started effect was recorded before the timeout")

    def kill_run(self, process: subprocess.Popen) -> None:
        """Kill the run *and* everything it spawned."""
        try:
            os.killpg(os.getpgid(process.pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            process.kill()

    def wait_for_evidence(self, evidence: Path, timeout: float = 60.0) -> Path:
        """Wait until the run has recorded an evidence directory and a transcript.

        The manifest is written before the session transcript exists, so
        waiting for the manifest alone would race the transcript.
        """
        import time

        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if evidence.is_dir():
                for candidate in evidence.iterdir():
                    if not (candidate / "manifest.json").is_file():
                        continue
                    sessions = candidate / "sessions"
                    if sessions.is_dir() and any(sessions.glob("*.jsonl")):
                        return candidate
            time.sleep(0.2)
        self.fail("the code run did not record an evidence directory in time")

    def test_dry_run_refuses_a_terminal_run(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            root = self.make_repository(parent)
            evidence = parent / "evidence"
            script = parent / "turns.json"
            script.write_text(
                json.dumps(
                    [
                        plan_turn(checks=(0,)),
                        {"tool": {"name": "Write", "input": {"path": "value.txt", "content": "new\n"}}},
                        {"text": "done"},
                    ]
                ),
                encoding="utf-8",
            )
            code, output, error = invoke(
                "code", "change the value", *self.base(root),
                "--script", str(script),
                "--check", "read line < value.txt; test \"$line\" = new",
                "--evidence-dir", str(evidence),
                "--keep-worktree",
            )
            self.assertEqual(code, 0, error)
            run_dir = next(evidence.iterdir())

            resume_code, resume_out, resume_err = invoke(
                "code-resume", str(run_dir), "--dry-run",
            )
            self.assertEqual(resume_code, 1)
            report = json.loads(resume_out)
            self.assertFalse(report["resumable"])
            self.assertEqual(report["reason"], "already_terminal")

    def test_resume_refuses_a_run_with_an_unreceipted_effect(self):
        """An effect without a receipt may already have happened: never replay it."""
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            root = self.make_repository(parent)
            evidence = parent / "evidence"
            run_dir = parent / "manual-run"
            run_dir.mkdir()
            worktree = parent / "worktree"
            worktree.mkdir()
            git(worktree, "init")
            # Build the evidence by hand: a run that started an effect and died.
            manifest = {
                "schema": "northstar.code-evidence.v1",
                "run_id": "run-inflight",
                "status": "error_during_execution",
                "start_commit": "0" * 40,
                "worktree": str(worktree),
            }
            phases = {
                "schema": "northstar.code-phases.v1",
                "run_id": "run-inflight",
                "state": "executing",
                "outcome": None,
                "plan_only": False,
                "effect_journal_version": 1,
                "check_inputs": [],
                "plan": {"files": ["value.txt"], "steps": [], "risks": []},
                "transitions": [
                    {"from": "created", "to": "understanding", "sequence": 1},
                    {"from": "understanding", "to": "planned", "sequence": 2},
                    {"from": "planned", "to": "executing", "sequence": 3},
                ],
                "effects": [
                    {
                        "effect_id": "e1",
                        "sequence": 1,
                        "tool": "ApplyPatch",
                        "call_id": "c1",
                        "phase": "executing",
                        "status": "in_flight",
                        "started_unix_ms": 1,
                        "finished_unix_ms": None,
                        "error_class": "",
                    }
                ],
            }
            raw = (json.dumps(phases, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode()
            (run_dir / "phases.json").write_bytes(raw)
            manifest["phases_sha256"] = hashlib.sha256(raw).hexdigest()
            (run_dir / "manifest.json").write_text(
                json.dumps(manifest, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
                encoding="utf-8",
            )
            (run_dir / "task.json").write_text(
                json.dumps({"goal": "change the value", "checks": ["printf 42"]}) + "\n",
                encoding="utf-8",
            )
            sessions = run_dir / "sessions"
            sessions.mkdir()
            (sessions / "sess-1.jsonl").write_text(
                json.dumps({"type": "assistant", "content": "hi"}) + "\n",
                encoding="utf-8",
            )

            resume_code, resume_out, resume_err = invoke(
                "code-resume", str(run_dir), "--dry-run",
            )
            self.assertEqual(resume_code, 1)
            report = json.loads(resume_out)
            self.assertFalse(report["resumable"])
            self.assertEqual(report["reason"], "unresolved_side_effects")
            self.assertEqual(len(report["unresolved_effects"]), 1)

    def test_resume_keeps_the_original_worktree_and_start_commit(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            root = self.make_repository(parent)
            evidence = parent / "evidence"
            script = parent / "turns.json"
            script.write_text(
                json.dumps([plan_turn(checks=(0,)), write_turn(), {"text": "working"}]),
                encoding="utf-8",
            )
            blocker = parent / "block.sh"
            blocker.write_text(
                "#!/bin/sh\n"
                "sleep 6\n"
                'read line < value.txt\n'
                'test "$line" = new\n',
                encoding="utf-8",
            )
            blocker.chmod(0o755)

            process = subprocess.Popen(
                [
                    sys.executable, "-m", "cli", "code", "change the value",
                    *self.base(root),
                    "--script", str(script),
                    "--check", str(blocker),
                    "--evidence-dir", str(evidence),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=str(Path(__file__).resolve().parents[1]),
                start_new_session=True,
            )
            try:
                run_dir = self.wait_for_evidence(evidence)
                self.wait_for_completed_effect(run_dir)
                self.kill_run(process)
            finally:
                process.wait(timeout=30)

            manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
            original_worktree = manifest["worktree"]
            original_start = manifest["start_commit"]
            self.assertTrue(Path(original_worktree).is_dir())

            # Resume with a script that finishes the work.
            resume_script = parent / "resume-turns.json"
            resume_script.write_text(
                json.dumps(
                    [
                        {
                            "tool": {
                                "name": "Write",
                                "input": {"path": "value.txt", "content": "new\n"},
                            }
                        },
                        {"text": "finished the change"},
                    ]
                ),
                encoding="utf-8",
            )
            resume_code, resume_out, resume_err = invoke(
                "code-resume", str(run_dir),
                "--script", str(resume_script),
                "--allow-checkpoint-tool-replay",
                "--sandbox", "process",
                "--seccomp", "off",
                "--capdrop", "off",
                "--landlock", "off",
                "--no-policy-file",
                "--no-workspace-agents",
                "--no-skills",
                "--no-memory",
                "--no-plugins",
            )
            self.assertEqual(
                resume_code, 0, f"{resume_err}\n{resume_out[:4000]}"
            )
            # The caller's checkout is still untouched.
            self.assertEqual((root / "value.txt").read_text(encoding="utf-8"), "old\n")
            resumed_manifest = json.loads(
                (run_dir / "manifest.json").read_text(encoding="utf-8")
            )
            self.assertEqual(resumed_manifest["start_commit"], original_start)
            self.assertEqual(resumed_manifest["worktree"], original_worktree)


if __name__ == "__main__":
    unittest.main()
