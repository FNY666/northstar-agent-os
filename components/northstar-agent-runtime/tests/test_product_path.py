"""Product path defaults: agent/resume weld session + checkpoints without loosening the gate.

P2 pins the resume contract the spine promised:

* product ``resume`` **forks** from a checkpoint (``--resume-from``), so consumed
  turns / tool calls / cost inherit and the parent transcript stays byte-identical;
* ``latest`` resolves to the newest transcript under the product session dir;
* ``--in-place`` is the documented escape back to append-only ``--resume``.
"""
from __future__ import annotations

import json
import tempfile
import time
import unittest
from pathlib import Path

import support  # noqa: F401
from support import text_turn  # noqa: F401

from product_path import (
    DEFAULT_CHECKPOINT_TURNS,
    apply_agent_defaults,
    extract_positional_task,
    apply_resume_defaults,
    default_session_dir,
    resolve_session_dir,
    resolve_session_id,
    resolve_workspace,
)


def run_cli(*argv: str) -> tuple[int, str, str]:
    import contextlib
    import io
    import sys

    from cli import main

    out, err = io.StringIO(), io.StringIO()
    saved, sys.stdin = sys.stdin, io.StringIO("")
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(list(argv))
    finally:
        sys.stdin = saved
    return code, out.getvalue(), err.getvalue()


class ProductPathUnitTests(unittest.TestCase):
    def test_default_session_dir_is_under_workspace_northstar(self):
        path = default_session_dir("/tmp/ws")
        self.assertTrue(path.is_absolute())
        self.assertTrue(str(path).endswith(".northstar/sessions") or str(path).endswith(".northstar\\sessions"))

    def test_resolve_workspace_reads_flag_or_dot(self):
        self.assertEqual(resolve_workspace(["--workspace", "/tmp/ws", "--prompt", "hi"]), "/tmp/ws")
        self.assertEqual(resolve_workspace(["--prompt", "hi"]), ".")
        self.assertEqual(resolve_workspace(["--workspace=/tmp/eq"]), "/tmp/eq")

    def test_resolve_session_dir_prefers_explicit(self):
        self.assertEqual(
            resolve_session_dir(["--session-dir", "/tmp/custom", "--workspace", "/tmp/ws"]),
            Path("/tmp/custom").resolve(),
        )
        self.assertEqual(
            resolve_session_dir(["--workspace", "/tmp/ws"]),
            default_session_dir("/tmp/ws"),
        )

    def test_resolve_session_id_passes_through_concrete_ids(self):
        self.assertEqual(resolve_session_id("ns-abc", "/tmp/missing"), "ns-abc")

    def test_resolve_session_id_latest_picks_newest_jsonl(self):
        root = Path(tempfile.mkdtemp(prefix="nsar-latest-"))
        older = root / "ns-old.jsonl"
        newer = root / "ns-new.jsonl"
        older.write_text("{}\n", encoding="utf-8")
        time.sleep(0.02)
        newer.write_text("{}\n", encoding="utf-8")
        self.assertEqual(resolve_session_id("latest", root), "ns-new")
        self.assertEqual(resolve_session_id("@latest", root), "ns-new")
        self.assertEqual(resolve_session_id(".", root), "ns-new")

    def test_resolve_session_id_latest_refuses_empty_dir(self):
        root = Path(tempfile.mkdtemp(prefix="nsar-empty-"))
        with self.assertRaises(ValueError) as caught:
            resolve_session_id("latest", root)
        self.assertIn("no transcripts", str(caught.exception).lower())

    def test_injects_session_dir_and_checkpoint_when_silent(self):
        out = apply_agent_defaults(["--workspace", "/tmp/ws", "--prompt", "hi"])
        self.assertIn("--session-dir", out)
        idx = out.index("--session-dir")
        self.assertEqual(out[idx + 1], str(default_session_dir("/tmp/ws")))
        self.assertIn("--checkpoint-turns", out)
        self.assertEqual(out[out.index("--checkpoint-turns") + 1], str(DEFAULT_CHECKPOINT_TURNS))

    def test_operator_session_dir_wins(self):
        out = apply_agent_defaults(["--workspace", "/tmp/ws", "--session-dir", "/tmp/custom", "--prompt", "hi"])
        self.assertEqual(out.count("--session-dir"), 1)
        self.assertEqual(out[out.index("--session-dir") + 1], "/tmp/custom")

    def test_operator_checkpoint_wins(self):
        out = apply_agent_defaults(["--checkpoint-turns", "3", "--prompt", "hi"])
        self.assertEqual(out.count("--checkpoint-turns"), 1)
        self.assertEqual(out[out.index("--checkpoint-turns") + 1], "3")

    def test_no_session_strips_injection(self):
        out = apply_agent_defaults(["--no-session", "--prompt", "hi", "--workspace", "/tmp/ws"])
        self.assertNotIn("--session-dir", out)
        self.assertNotIn("--no-session", out)
        # checkpoints still default on unless also opted out
        self.assertIn("--checkpoint-turns", out)

    def test_no_checkpoint_strips_injection(self):
        out = apply_agent_defaults(["--no-checkpoint", "--prompt", "hi"])
        self.assertNotIn("--checkpoint-turns", out)
        self.assertNotIn("--no-checkpoint", out)
        self.assertIn("--session-dir", out)

    def test_never_injects_allow_or_hooks(self):
        out = apply_agent_defaults(["--prompt", "hi"])
        joined = " ".join(out)
        self.assertNotIn("--allow-tool", joined)
        self.assertNotIn("--enable-workspace-hooks", joined)
        self.assertNotIn("bypassPermissions", joined)

    def test_a_released_mcp_variable_is_not_mistaken_for_the_task(self):
        # `northstar agent TASK` has to tell a bare task from a flag's value, and `--mcp-env`
        # (F5) is exactly the kind of flag that trips it up: one that takes a name. A boolean
        # like `--mcp-allow-exec` must *not* be added to the value-taking set, or the task would
        # start being eaten by a flag with no argument.
        argv, task = extract_positional_task(["agent", "--mcp-env", "HOME", "fix the flake"])
        self.assertEqual(task, "fix the flake")
        self.assertIn("--mcp-env", argv)
        self.assertNotIn("HOME", task)
        _argv, second = extract_positional_task(["agent", "--mcp-allow-exec", "fix the flake"])
        self.assertEqual(second, "fix the flake")


class ResumeDefaultsUnitTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="nsar-resume-unit-"))
        # Product default path: transcripts live under <workspace>/.northstar/sessions.
        self.sessions = self.root / ".northstar" / "sessions"
        self.sessions.mkdir(parents=True)
        (self.sessions / "ns-parent.jsonl").write_text("{}\n", encoding="utf-8")

    def test_product_resume_forks_via_resume_from(self):
        out = apply_resume_defaults(
            ["--workspace", str(self.root), "--prompt", "go"],
            session_id="ns-parent",
        )
        self.assertEqual(out[-2:], ["--resume-from", "ns-parent"])
        self.assertNotIn("--resume", out)
        self.assertIn("--session-dir", out)
        self.assertIn("--checkpoint-turns", out)

    def test_in_place_uses_append_resume(self):
        out = apply_resume_defaults(
            ["--workspace", str(self.root), "--prompt", "go", "--in-place"],
            session_id="ns-parent",
        )
        self.assertEqual(out[-2:], ["--resume", "ns-parent"])
        self.assertNotIn("--resume-from", out)
        self.assertNotIn("--in-place", out)

    def test_latest_resolves_against_the_session_dir(self):
        out = apply_resume_defaults(
            ["--workspace", str(self.root), "--prompt", "go"],
            session_id="latest",
        )
        self.assertEqual(out[-2:], ["--resume-from", "ns-parent"])

    def test_rejects_low_level_resume_flags(self):
        with self.assertRaises(ValueError):
            apply_resume_defaults(["--resume", "ns-other", "--prompt", "x"], session_id="ns-abc")
        with self.assertRaises(ValueError):
            apply_resume_defaults(["--resume-from", "ns-other", "--prompt", "x"], session_id="ns-abc")

    def test_no_session_on_resume_is_configuration_error(self):
        with self.assertRaises(ValueError) as caught:
            apply_resume_defaults(
                ["--workspace", str(self.root), "--no-session", "--prompt", "x"],
                session_id="ns-parent",
            )
        self.assertIn("session directory", str(caught.exception).lower())


class AgentCommandTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="nsar-agent-"))
        self.workspace = self.tmp / "ws"
        self.workspace.mkdir()
        (self.workspace / "note.txt").write_text("hello product path\n", encoding="utf-8")

    def test_agent_writes_session_under_workspace_northstar_by_default(self):
        code, out, err = run_cli(
            "agent",
            "--workspace",
            str(self.workspace),
            "--prompt",
            "say hi",
            "--scripted-text",
            "hello",
            "--quiet",
        )
        self.assertEqual(code, 0, err)
        self.assertIn("[success]", out)
        session_root = self.workspace / ".northstar" / "sessions"
        self.assertTrue(session_root.is_dir(), "product path must create the default session dir")
        files = list(session_root.glob("*.jsonl"))
        self.assertEqual(len(files), 1, files)
        body = files[0].read_text(encoding="utf-8")
        self.assertIn("say hi", body)
        # Compact JSONL: no space after the colon.
        self.assertIn('"type":"checkpoint"', body, "default cadence is every turn, so a boundary must land")

    def test_agent_no_session_matches_kernel_silence(self):
        code, out, err = run_cli(
            "agent",
            "--workspace",
            str(self.workspace),
            "--prompt",
            "quiet",
            "--scripted-text",
            "ok",
            "--no-session",
            "--quiet",
        )
        self.assertEqual(code, 0, err)
        self.assertFalse((self.workspace / ".northstar" / "sessions").exists())

    def test_agent_does_not_loosen_the_gate(self):
        script = self.workspace / "s.json"
        script.write_text(
            json.dumps([{"tool": {"name": "Write", "input": {"path": "x.txt", "content": "nope"}}}, {"text": "noted"}]),
            encoding="utf-8",
        )
        code, out, err = run_cli(
            "agent",
            "--workspace",
            str(self.workspace),
            "--prompt",
            "write",
            "--script",
            str(script),
            "--json",
        )
        self.assertEqual(code, 0, err)
        events = [json.loads(line) for line in out.splitlines()]
        denial = events[2]["content"][0]
        self.assertTrue(denial["is_error"])
        self.assertFalse((self.workspace / "x.txt").exists())

    def test_agent_help_documents_product_opt_outs(self):
        import contextlib
        import io

        from cli import build_parser

        parser = build_parser()
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            with self.assertRaises(SystemExit) as caught:
                parser.parse_args(["agent", "--help"])
        self.assertEqual(caught.exception.code, 0)
        help_text = buf.getvalue()
        self.assertIn("--no-session", help_text)
        self.assertIn("--no-checkpoint", help_text)
        self.assertIn("session", help_text.lower())


class ResumeCommandTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="nsar-resume-"))
        self.workspace = self.tmp / "ws"
        self.workspace.mkdir()

    def _session_id_from_quiet(self, out: str) -> str:
        # quiet line ends with `session=<id>`
        marker = "session="
        self.assertIn(marker, out)
        return out.strip().split(marker)[1].split()[0]

    def test_resume_forks_a_child_and_leaves_the_parent_alone(self):
        code, out, err = run_cli(
            "agent",
            "--workspace",
            str(self.workspace),
            "--prompt",
            "first",
            "--scripted-text",
            "answer-one",
            "--quiet",
        )
        self.assertEqual(code, 0, err)
        parent_id = self._session_id_from_quiet(out)
        parent_path = self.workspace / ".northstar" / "sessions" / f"{parent_id}.jsonl"
        parent_bytes = parent_path.read_bytes()

        code, out, err = run_cli(
            "resume",
            parent_id,
            "--workspace",
            str(self.workspace),
            "--prompt",
            "second",
            "--scripted-text",
            "answer-two",
            "--json",
        )
        self.assertEqual(code, 0, err)
        events = [json.loads(line) for line in out.splitlines()]
        init = events[0]
        self.assertEqual(init["type"], "system")
        resumed = init["data"]["resumed_from"]
        self.assertEqual(resumed["parent_session"], parent_id)
        self.assertTrue(resumed["forked"])
        self.assertGreaterEqual(resumed["turns_inherited"], 1)

        # Parent file byte-identical; child is a new transcript.
        self.assertEqual(parent_path.read_bytes(), parent_bytes)
        child_id = events[-1]["session_id"]
        self.assertNotEqual(child_id, parent_id)
        child_body = (self.workspace / ".northstar" / "sessions" / f"{child_id}.jsonl").read_text(encoding="utf-8")
        self.assertIn("second", child_body)
        self.assertIn("answer-two", child_body)
        self.assertIn('"type":"checkpoint"', child_body)

    def test_resume_latest_picks_the_newest_parent(self):
        code, out, err = run_cli(
            "agent",
            "--workspace",
            str(self.workspace),
            "--prompt",
            "first",
            "--scripted-text",
            "one",
            "--quiet",
        )
        self.assertEqual(code, 0, err)
        parent_id = self._session_id_from_quiet(out)

        code, out, err = run_cli(
            "resume",
            "latest",
            "--workspace",
            str(self.workspace),
            "--prompt",
            "second",
            "--scripted-text",
            "two",
            "--json",
        )
        self.assertEqual(code, 0, err)
        init = json.loads(out.splitlines()[0])
        self.assertEqual(init["data"]["resumed_from"]["parent_session"], parent_id)

    def test_resume_inherits_budget_so_ceilings_bind_the_lineage(self):
        """The spine invariant: resume must not launder a spent budget."""
        script = self.workspace / "costly.json"
        script.write_text(
            json.dumps([{"text": "costly", "usage": {"input_tokens": 2_000_000}}]),
            encoding="utf-8",
        )
        code, out, err = run_cli(
            "agent",
            "--workspace",
            str(self.workspace),
            "--script",
            str(script),
            "--prompt",
            "go",
            "--max-budget-usd",
            "100",
            "--quiet",
        )
        self.assertEqual(code, 0, err)
        parent_id = self._session_id_from_quiet(out)

        # Cap below what the parent already spent → resume must refuse before a turn.
        code, out, err = run_cli(
            "resume",
            parent_id,
            "--workspace",
            str(self.workspace),
            "--prompt",
            "continue",
            "--scripted-text",
            "one more thing",
            "--max-budget-usd",
            "1",
            "--quiet",
        )
        self.assertEqual(code, 4, err or out)  # error_max_budget_usd
        self.assertIn("error_max_budget_usd", out)
        self.assertNotIn("one more thing", out)

    def test_in_place_appends_to_the_same_file(self):
        code, out, err = run_cli(
            "agent",
            "--workspace",
            str(self.workspace),
            "--prompt",
            "first",
            "--scripted-text",
            "answer-one",
            "--quiet",
        )
        self.assertEqual(code, 0, err)
        parent_id = self._session_id_from_quiet(out)
        code, out, err = run_cli(
            "resume",
            parent_id,
            "--workspace",
            str(self.workspace),
            "--prompt",
            "second",
            "--scripted-text",
            "answer-two",
            "--in-place",
            "--quiet",
        )
        self.assertEqual(code, 0, err)
        self.assertIn(parent_id, out)
        transcript = (self.workspace / ".northstar" / "sessions" / f"{parent_id}.jsonl").read_text(encoding="utf-8")
        self.assertIn("first", transcript)
        self.assertIn("second", transcript)
        self.assertIn("answer-two", transcript)

    def test_resume_without_session_id_is_usage_error(self):
        code, _, err = run_cli("resume", "--prompt", "x", "--scripted-text", "y")
        self.assertEqual(code, 64)
        self.assertIn("session id", err.lower())

    def test_resume_help_documents_fork_and_latest(self):
        import contextlib
        import io

        from cli import build_parser

        parser = build_parser()
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            with self.assertRaises(SystemExit) as caught:
                parser.parse_args(["resume", "--help"])
        self.assertEqual(caught.exception.code, 0)
        help_text = buf.getvalue()
        self.assertIn("latest", help_text)
        self.assertIn("--in-place", help_text)
        self.assertIn("fork", help_text.lower())


class SessionsProductDefaultTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="nsar-sess-"))
        self.workspace = self.tmp / "ws"
        self.workspace.mkdir()

    def test_sessions_list_defaults_to_product_session_dir(self):
        code, out, err = run_cli(
            "agent",
            "--workspace",
            str(self.workspace),
            "--prompt",
            "hi",
            "--scripted-text",
            "hello",
            "--quiet",
        )
        self.assertEqual(code, 0, err)
        code, out, err = run_cli("sessions", "list", "--workspace", str(self.workspace))
        self.assertEqual(code, 0, err)
        self.assertIn("ns-", out)

    def test_sessions_show_latest(self):
        code, out, err = run_cli(
            "agent",
            "--workspace",
            str(self.workspace),
            "--prompt",
            "hi",
            "--scripted-text",
            "hello",
            "--quiet",
        )
        self.assertEqual(code, 0, err)
        code, out, err = run_cli(
            "sessions", "show", "--workspace", str(self.workspace), "latest"
        )
        self.assertEqual(code, 0, err)
        self.assertIn("hi", out)


if __name__ == "__main__":
    unittest.main()
