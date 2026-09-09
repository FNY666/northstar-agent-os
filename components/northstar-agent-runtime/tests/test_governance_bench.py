"""Public governance benchmark + minimal product interaction (P5)."""
from __future__ import annotations

import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

import support  # noqa: F401 — sys.path bootstrap
from support import text_turn

from governance_bench import BENCH_VERSION, CASES, list_cases, run_suite
from product_path import apply_agent_defaults, extract_positional_task


def run_cli(*argv: str, stdin_text: str = "") -> tuple[int, str, str]:
    from cli import main

    out, err = io.StringIO(), io.StringIO()
    saved, sys.stdin = sys.stdin, io.StringIO(stdin_text)
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(list(argv))
    finally:
        sys.stdin = saved
    return code, out.getvalue(), err.getvalue()


class GovernanceBenchUnitTests(unittest.TestCase):
    def test_case_catalogue_is_non_empty_and_versioned(self):
        self.assertTrue(BENCH_VERSION.startswith("northstar.governance.bench."))
        self.assertGreaterEqual(len(CASES), 10)
        ids = [case.id for case in CASES]
        self.assertEqual(len(ids), len(set(ids)), "case ids must be unique")
        tracks = {case.track for case in CASES}
        self.assertEqual(tracks, {"denial", "injection", "budget"})

    def test_list_cases_matches_catalogue(self):
        rows = list_cases()
        self.assertEqual(len(rows), len(CASES))
        self.assertEqual(rows[0]["id"], CASES[0].id)

    def test_full_suite_passes_offline(self):
        report = run_suite()
        self.assertTrue(report.ok, [c.as_dict() for c in report.cases if not c.ok])
        self.assertEqual(report.failed, 0)
        self.assertEqual(report.total, len(CASES))
        self.assertEqual(report.version, BENCH_VERSION)
        self.assertIn("denial", report.tracks)
        self.assertIn("injection", report.tracks)
        self.assertIn("budget", report.tracks)

    def test_only_filter_selects_one_track(self):
        report = run_suite(tracks=["budget"])
        self.assertTrue(report.ok)
        self.assertTrue(all(c.track == "budget" for c in report.cases))
        self.assertGreaterEqual(report.total, 3)

    def test_unknown_only_is_a_configuration_error(self):
        with self.assertRaises(ValueError):
            run_suite(only=["does.not.exist"])


class GovernanceBenchCliTests(unittest.TestCase):
    def test_bench_list_prints_ids(self):
        code, out, err = run_cli("bench", "--list")
        self.assertEqual(code, 0, err)
        self.assertIn(BENCH_VERSION, out)
        self.assertIn("denial.shell_default_deny", out)
        self.assertIn("budget.max_budget_usd", out)

    def test_bench_list_json(self):
        code, out, _ = run_cli("bench", "--list", "--json")
        self.assertEqual(code, 0)
        payload = json.loads(out)
        self.assertEqual(payload["type"], "governance-bench-list")
        self.assertEqual(payload["version"], BENCH_VERSION)
        self.assertGreaterEqual(len(payload["cases"]), 10)

    def test_bench_run_passes(self):
        code, out, err = run_cli("bench")
        self.assertEqual(code, 0, err + out)
        self.assertIn("PASS", out)
        self.assertIn(BENCH_VERSION, out)

    def test_bench_run_json_shape(self):
        code, out, err = run_cli("bench", "--json")
        self.assertEqual(code, 0, err)
        payload = json.loads(out)
        self.assertEqual(payload["type"], "governance-bench")
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["failed"], 0)
        self.assertEqual(payload["total"], len(CASES))

    def test_bench_is_on_the_top_level_help(self):
        code, out, _ = run_cli()
        self.assertEqual(code, 64)
        self.assertIn("bench", out)


class PositionalTaskTests(unittest.TestCase):
    def test_extract_positional_task_pulls_bare_string(self):
        body, task = extract_positional_task(["--workspace", "/tmp/ws", "summarise README"])
        self.assertEqual(task, "summarise README")
        self.assertEqual(body, ["--workspace", "/tmp/ws"])

    def test_extract_respects_double_dash(self):
        body, task = extract_positional_task(["--workspace", ".", "--", "do", "this"])
        self.assertEqual(task, "do this")
        self.assertEqual(body, ["--workspace", "."])

    def test_multiple_bare_tokens_are_refused(self):
        with self.assertRaises(ValueError):
            extract_positional_task(["one", "two"])

    def test_apply_agent_defaults_rewrites_task_to_prompt(self):
        welded = apply_agent_defaults(["--workspace", "/tmp/ws", "hello world"])
        self.assertIn("--prompt", welded)
        self.assertIn("hello world", welded)
        self.assertIn("--session-dir", welded)
        self.assertIn("--checkpoint-turns", welded)

    def test_positional_plus_prompt_flag_is_refused(self):
        with self.assertRaises(ValueError):
            apply_agent_defaults(["--prompt", "a", "b"])

    def test_cli_agent_accepts_positional_task(self):
        root = Path(tempfile.mkdtemp(prefix="ns-task-"))
        (root / "notes.txt").write_text("hi\n", encoding="utf-8")
        code, out, err = run_cli(
            "agent",
            "--workspace",
            str(root),
            "say hello",
            "--provider",
            "scripted",
            "--scripted-text",
            "hello from positional",
            "--no-session",
            "--no-checkpoint",
            "--json",
        )
        self.assertEqual(code, 0, err + out)
        # The welded positional task must reach the loop: a successful result
        # with the scripted reply proves --prompt was injected.
        self.assertIn("hello from positional", out)
        self.assertIn('"subtype":"success"', out.replace(" ", ""))


if __name__ == "__main__":
    unittest.main()
