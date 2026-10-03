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
        self.assertEqual(tracks, {"denial", "injection", "budget", "metrics"})

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


class ConsentAblationTests(unittest.TestCase):
    def test_consent_ablation_is_deterministic(self):
        from governance_bench import run_consent_ablation

        first = run_consent_ablation()
        second = run_consent_ablation()
        self.assertEqual(first, second)

    def test_consent_ablation_flip_pattern(self):
        from governance_bench import run_consent_ablation

        ablation = run_consent_ablation()
        self.assertEqual(ablation["n_probes"], 6)
        # The three consent-gated mutating probes flip allow->deny; nothing
        # may flip deny->allow (stripping consent must never grant access).
        self.assertEqual(len(ablation["flip_allow_to_deny"]), 3)
        self.assertEqual(ablation["flip_deny_to_allow"], [])
        self.assertEqual(set(ablation["flip_tiers"]), {"3"})
        # Controls: the read probe stays allowed, the disallowed and the
        # empty-consent probes stay denied in both passes.
        self.assertEqual(ablation["kept"]["allowed"], 4)
        self.assertEqual(ablation["stripped"]["allowed"], 1)

    def test_consent_case_is_registered(self):
        import inspect

        from governance_bench import _case_metrics_consent_ablation

        case = next(c for c in CASES if c.id == "metrics.consent_ablation")
        self.assertEqual(case.track, "metrics")
        # The honest scoping must live in the case source: deterministic
        # engine sensitivity, NOT a human-subject experiment.
        src = inspect.getsource(_case_metrics_consent_ablation)
        self.assertIn("NOT a human-subject experiment", src)


class OwaspAsiCoverageTests(unittest.TestCase):
    def test_owasp_asi_is_deterministic(self):
        from governance_bench import run_owasp_asi_coverage

        first = run_owasp_asi_coverage()
        second = run_owasp_asi_coverage()
        self.assertEqual(first, second)

    def test_owasp_asi_coverage_numbers(self):
        from governance_bench import OWASP_ASI, run_owasp_asi_coverage

        coverage = run_owasp_asi_coverage()
        # Ten entries, cross-verified against independent sources.
        self.assertEqual(coverage["total"], 10)
        self.assertEqual(
            sorted(e["id"] for e in OWASP_ASI),
            [f"ASI{i:02d}" for i in range(1, 11)],
        )
        # 7 covered, 3 residual partials; every gap probe meets its closed
        # expectation and no mapping points at a case that does not exist.
        self.assertEqual(coverage["covered"], 7)
        self.assertEqual(coverage["gaps"], ["ASI04", "ASI07", "ASI10"])
        self.assertEqual(coverage["gap_probe_mismatches"], [])
        self.assertEqual(coverage["unknown_case_refs"], [])
        self.assertEqual(coverage["n_gap_probes"], 4)
        # The ten titles must match the cross-verified strings.
        titles = {e["id"]: e["title"] for e in OWASP_ASI}
        self.assertEqual(titles["ASI01"], "Agent Goal Hijack")
        self.assertEqual(titles["ASI02"], "Tool Misuse & Exploitation")
        self.assertEqual(titles["ASI03"], "Identity & Privilege Abuse")
        self.assertEqual(titles["ASI04"], "Agentic Supply Chain Vulnerabilities")
        self.assertEqual(titles["ASI05"], "Unexpected Code Execution")
        self.assertEqual(titles["ASI06"], "Memory & Context Poisoning")
        self.assertEqual(titles["ASI07"], "Insecure Inter-Agent Communication")
        self.assertEqual(titles["ASI08"], "Cascading Failures")
        self.assertEqual(titles["ASI09"], "Human-Agent Trust Exploitation")
        self.assertEqual(titles["ASI10"], "Rogue Agents")

    def test_owasp_case_is_registered(self):
        import inspect

        from governance_bench import _case_metrics_owasp_asi_coverage

        case = next(c for c in CASES if c.id == "metrics.owasp_asi_coverage")
        self.assertEqual(case.track, "metrics")
        # The honest scoping must live in the case source: offline-gate
        # coverage, NOT an official OWASP conformance claim, and the PDF
        # limitation must be stated.
        src = inspect.getsource(_case_metrics_owasp_asi_coverage)
        self.assertIn("NOT", src)
        self.assertIn("official OWASP conformance claim", src)
        self.assertIn("download form", src)

class LeastPrivilegeTests(unittest.TestCase):
    def test_least_privilege_is_deterministic(self):
        from governance_bench import run_least_privilege

        first = run_least_privilege()
        second = run_least_privilege()
        self.assertEqual(first, second)

    def test_least_privilege_opur_baseline(self):
        from governance_bench import run_least_privilege

        result = run_least_privilege()
        self.assertEqual(result["n_probes"], 23)
        # 15 over-privileged reaches eligible; the gate must deny them all.
        self.assertEqual(result["opur_eligible"], 15)
        self.assertEqual(result["opur_allowed"], 0)
        self.assertEqual(result["opur"], 0.0)
        self.assertEqual(result["over_priv_block_rate"], 1.0)
        # Precision: the 5 sufficient-tool controls stay allowed (not deny-all).
        self.assertEqual(result["precision_n"], 5)
        self.assertEqual(result["precision_allow_rate"], 1.0)
        # The 3 legit high-privilege controls stay allowed, outside the OPUR
        # denominator.
        self.assertEqual(result["legit_excluded_n"], 3)
        self.assertEqual(result["legit_allowed"], 3)
        # The transient-failure amplifier must not move the deterministic gate.
        self.assertEqual(result["amplifier_decision_changes"], [])
        # All five risk patterns and all three PED classes are covered and
        # fully blocked.
        self.assertEqual(len(result["by_pattern"]), 5)
        for stats in result["by_pattern"].values():
            self.assertEqual(stats["block_rate"], 1.0)
        for stats in result["by_ped_class"].values():
            self.assertEqual(stats["block_rate"], 1.0)

    def test_least_privilege_corpus_is_original_synthetic(self):
        # Methodology-inspired, not dataset-copied: every probe id uses the
        # lp_ prefix and no probe text comes from the official dataset.
        from governance_bench import LEAST_PRIV_CORPUS

        self.assertEqual(len(LEAST_PRIV_CORPUS), 23)
        for probe in LEAST_PRIV_CORPUS:
            self.assertTrue(probe.id.startswith("lp_"), probe.id)
            self.assertEqual(probe.callback, "least_priv")
            self.assertEqual(probe.expect_tier, 3)

    def test_least_privilege_case_is_registered(self):
        import inspect

        from governance_bench import _case_metrics_least_privilege

        case = next(c for c in CASES if c.id == "metrics.least_privilege")
        self.assertEqual(case.track, "metrics")
        # The honest scoping must live in the case source: original
        # synthetic corpus, NOT the official dataset; enforcement, NOT
        # model behavior.
        src = inspect.getsource(_case_metrics_least_privilege)
        self.assertIn("NOT the", src)
        self.assertIn("official ToolPrivBench dataset", src)


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
