"""Guards on the distribution tool.

The tool exists to inform a later decision, so the tests it needs are about
refusing to overstate: an unreadable or unavailable sample must be skipped
rather than counted, a missing verdict must stay `unknown`, and the summary must
never read as a decision.
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
COMPONENTS = ROOT.parent
for candidate in (ROOT, COMPONENTS / "northstar-run-contract", COMPONENTS / "northstar-host"):
    if str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))

from advisory_report import (  # noqa: E402
    PRODUCTION_SOURCE,
    SHADOW_SOURCE,
    UNKNOWN,
    Sample,
    collect_paths,
    load_samples,
    render_markdown,
    sample_from_production,
    sample_from_shadow,
    summarize,
)
from completion_advisory import DriverAdvisory, verify_advisory_digest  # noqa: E402
from completion_contract_v2 import CompletionResult, WorkspaceSnapshot  # noqa: E402
from completion_live_shadow import production_result_from_host_check  # noqa: E402
from completion_shadow import compose_shadow  # noqa: E402


def shadow_report(production: str, contract: str, layered: str) -> dict:
    return {
        "production": {"verdict": production},
        "contract": {"verdict": contract},
        "layered": {"verdict": layered},
    }


def production_report(ok: bool, production: str, contract: str, layered: str) -> dict:
    return {
        "ok": ok,
        "shadow_advisory": {
            "schema_version": "northstar.completion-advisory.v1",
            "available": True,
            "production_verdict": production,
            "contract_verdict": contract,
            "layered_verdict": layered,
        },
    }


class NormalisationTest(unittest.TestCase):
    def test_shadow_report_is_read_from_its_nested_verdicts(self):
        sample = sample_from_shadow(shadow_report("verified", "failed", "failed"), "r.json")
        self.assertEqual(sample.source, SHADOW_SOURCE)
        self.assertEqual((sample.production, sample.contract, sample.layered), ("verified", "failed", "failed"))

    def test_production_report_is_read_from_its_advisory(self):
        sample = sample_from_production(production_report(True, "verified", "verified", "verified"), "r.json")
        self.assertEqual(sample.source, PRODUCTION_SOURCE)
        self.assertEqual(sample.layered, "verified")

    def test_production_report_without_an_advisory_is_not_a_sample(self):
        self.assertIsNone(sample_from_production({"ok": True}, "r.json"))

    def test_unavailable_advisory_is_not_counted_as_a_verdict(self):
        report = {"ok": True, "shadow_advisory": {"available": False, "reason": "advisory_error:KeyError"}}
        self.assertIsNone(sample_from_production(report, "r.json"))

    def test_missing_verdicts_stay_unknown_rather_than_being_filled_in(self):
        sample = sample_from_shadow({"production": {"verdict": "verified"}}, "r.json")
        self.assertEqual(sample.contract, UNKNOWN)
        self.assertEqual(sample.layered, UNKNOWN)
        self.assertNotEqual(sample.contract, "verified")

    def test_production_verdict_falls_back_without_claiming_a_failure(self):
        report = production_report(False, "", "", "unknown")
        sample = sample_from_production(report, "r.json")
        self.assertEqual(sample.production, "not-verified")


class LoadingTest(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        (self.root / "shadow.json").write_text(
            json.dumps(shadow_report("verified", "failed", "failed")), encoding="utf-8"
        )
        (self.root / "production.json").write_text(
            json.dumps(production_report(True, "verified", "failed", "failed")), encoding="utf-8"
        )
        (self.root / "plain.json").write_text(json.dumps({"ok": True}), encoding="utf-8")
        (self.root / "broken.json").write_text("{not json", encoding="utf-8")

    def test_unreadable_and_incomparable_reports_are_skipped_with_a_reason(self):
        paths = sorted(self.root.glob("*.json"))
        samples, skipped = load_samples(paths)
        self.assertEqual(len(samples), 2)
        joined = " ".join(skipped)
        self.assertIn("broken.json", joined)
        self.assertIn("plain.json", joined)


class SummaryTest(unittest.TestCase):
    def samples(self):
        return [
            sample_from_shadow(shadow_report("verified", "verified", "verified"), "a.json"),
            sample_from_shadow(shadow_report("verified", "failed", "failed"), "b.json"),
            sample_from_production(production_report(True, "verified", "failed", "failed"), "c.json"),
        ]

    def test_distribution_counts_every_combination(self):
        summary = summarize(self.samples())
        distribution = {
            (row["production"], row["contract"], row["layered"]): row["count"]
            for row in summary["distribution"]
        }
        self.assertEqual(distribution[("verified", "verified", "verified")], 1)
        self.assertEqual(distribution[("verified", "failed", "failed")], 2)
        self.assertEqual(summary["sample_count"], 3)
        self.assertEqual(summary["by_source"][SHADOW_SOURCE], 2)

    def test_disagreements_name_the_runs_a_reviewer_should_read(self):
        summary = summarize(self.samples())
        labels = {item["label"] for item in summary["gate_accepted_contract_disagreed"]}
        self.assertEqual(labels, {"b.json", "c.json"})

    def test_summary_states_it_is_not_a_decision(self):
        summary = summarize(self.samples())
        self.assertFalse(summary["is_a_decision"])
        self.assertFalse(summary["authoritative"])
        self.assertTrue(any("too small" in caveat for caveat in summary["caveats"]))

    def test_markdown_renders_the_same_counts(self):
        rendered = render_markdown(summarize(self.samples()))
        self.assertIn("| verified | failed | failed | 2 |", rendered)
        self.assertIn("sample_count: 3", rendered)


class DigestTest(unittest.TestCase):
    """Stamp through the real code path, then check what a reader can detect."""

    def stamped(self) -> dict:
        journal = Path(tempfile.mkdtemp()) / "round-1.evidence.jsonl"
        journal.write_text("", encoding="utf-8")
        host_check = production_result_from_host_check(
            verdict="verified",
            failures=(),
            checked=(),
            run_status="finished",
            after=WorkspaceSnapshot.from_files({"out/report.md": "x\n"}),
        )
        contract_result = CompletionResult("verified", (), ())
        advisory = DriverAdvisory(
            production=host_check,
            contract=contract_result,
            layered=compose_shadow(host_check, contract_result),
            evidence_path=journal,
        )
        return advisory.as_report_dict()

    def test_a_stamped_advisory_verifies_and_a_tampered_one_does_not(self):
        stamped = self.stamped()
        self.assertTrue(verify_advisory_digest(stamped))
        self.assertFalse(verify_advisory_digest({**stamped, "layered_verdict": "failed"}))
        self.assertFalse(verify_advisory_digest({**stamped, "evidence_journal": "/elsewhere"}))

    def test_an_unstamped_payload_never_verifies(self):
        self.assertFalse(verify_advisory_digest({"available": True, "layered_verdict": "verified"}))


    def test_samples_with_the_same_file_name_stay_distinguishable(self):
        """Report files share a name; a label must still identify the sample."""
        root = Path(tempfile.mkdtemp())
        for name in ("run-a", "run-b"):
            directory = root / name
            directory.mkdir()
            (directory / "report.json").write_text(
                json.dumps(shadow_report("verified", "failed", "failed")), encoding="utf-8"
            )
        samples, skipped = load_samples(collect_paths([str(root)]))
        self.assertEqual(skipped, [])
        labels = [sample.label for sample in samples]
        self.assertEqual(len(set(labels)), 2, labels)
        self.assertTrue(all("run-" in label for label in labels), labels)

    def test_markdown_rendering_keeps_the_caveats_and_the_disagreements(self):
        sample = Sample("harness-shadow", "run-a/report.json", "verified", "failed", "failed")
        rendered = render_markdown(summarize([sample]))
        self.assertIn("disagreement:", rendered)
        self.assertIn("caveats:", rendered)
        self.assertIn("is_a_decision: false", rendered)


    def test_noise_files_are_counted_but_only_actionable_skips_are_listed(self):
        root = Path(tempfile.mkdtemp())
        (root / "checkpoint.json").write_text(json.dumps({"sequence": 1}), encoding="utf-8")
        (root / "broken.json").write_text("{not json", encoding="utf-8")
        run = root / "run"
        run.mkdir()
        (run / "report.json").write_text(
            json.dumps(shadow_report("verified", "verified", "verified")), encoding="utf-8"
        )
        samples, skipped = load_samples(collect_paths([str(root)]))
        summary = summarize(samples, skipped)
        self.assertEqual(summary["sample_count"], 1)
        self.assertEqual(summary["skipped_by_reason"].get("not_a_report"), 1)
        self.assertEqual(summary["skipped_by_reason"].get("unreadable"), 1)
        self.assertEqual(len(summary["skipped_detail"]), 1, summary["skipped_detail"])
        self.assertIn("broken.json", summary["skipped_detail"][0])


if __name__ == "__main__":
    unittest.main()
