"""An agent that cannot keep a failure will pay for it again."""
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

COMPONENT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(COMPONENT_ROOT))
sys.path.insert(0, str(COMPONENT_ROOT.parent / "northstar-host"))
sys.path.insert(0, str(COMPONENT_ROOT.parent / "northstar-run-contract"))

from experience_ledger import ExperienceLedger, ExperienceRecord  # noqa: E402


def _failed():
    return ("failed", ("completion test exited with code 1",), {})


def _verified():
    return ("verified", (), {"report.md": "sha256:" + "a" * 64})


class ExperienceLedgerTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.path = Path(self.tempdir.name) / "experiences.jsonl"

    def tearDown(self):
        self.tempdir.cleanup()

    def _record(self, ledger, **overrides):
        payload = dict(
            verdict_result=_failed(),
            run_id="run-1",
            run_digest="sha256:" + "b" * 64,
            fingerprint="fix-failing-pytest",
            event_head="sha256:" + "c" * 64,
        )
        payload.update(overrides)
        return ledger.record(**payload)

    def test_a_failed_run_becomes_a_failure_experience(self):
        ledger = ExperienceLedger(self.path)
        record = self._record(ledger)
        self.assertEqual(record.kind, "failure")
        self.assertEqual(record.source_verdict, "failed")
        self.assertIn("exited with code 1", record.signals[0])

    def test_a_verified_run_becomes_a_success_experience(self):
        ledger = ExperienceLedger(self.path)
        record = self._record(ledger, verdict_result=_verified())
        self.assertEqual(record.kind, "success")
        self.assertEqual(record.source_verdict, "verified")
    def test_an_unknown_verdict_is_refused_rather_than_remembered(self):
        # An unresolved run teaches nothing, and remembering it as a lesson
        # would turn "we do not know" into "we learned this".
        ledger = ExperienceLedger(self.path)
        with self.assertRaises(ValueError):
            self._record(ledger, verdict_result=("unknown", ("no evidence of completion",), {}))

    def test_recall_returns_the_experiences_of_that_fingerprint_only(self):
        ledger = ExperienceLedger(self.path)
        self._record(ledger)
        self._record(ledger, run_id="run-2", fingerprint="write-migration")
        recalled = ledger.recall("fix-failing-pytest")
        self.assertEqual([record.source_run_id for record in recalled], ["run-1"])
        self.assertEqual(ledger.recall("never-seen"), ())

    def test_recording_the_same_run_twice_is_idempotent(self):
        ledger = ExperienceLedger(self.path)
        first = self._record(ledger)
        second = self._record(ledger)
        self.assertEqual(first.record_digest, second.record_digest)
        self.assertEqual(len(ledger.recall("fix-failing-pytest")), 1)

    def test_an_empty_ledger_reports_empty_rather_than_verified(self):
        recovery = ExperienceLedger(self.path).recover()
        self.assertEqual(recovery.verdict, "empty")
        self.assertEqual(recovery.records, ())
    def test_a_tampered_ledger_is_unverifiable(self):
        ledger = ExperienceLedger(self.path)
        self._record(ledger)
        lines = self.path.read_text(encoding="utf-8").splitlines()
        lines[0] = lines[0].replace("fix-failing-pytest", "fix-failing-other")
        self.path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        self.assertEqual(ExperienceLedger(self.path).recover().verdict, "unverifiable")

    def test_truncating_the_ledger_is_not_verified(self):
        ledger = ExperienceLedger(self.path)
        self._record(ledger)
        self.path.write_text("", encoding="utf-8")
        self.assertEqual(ExperienceLedger(self.path).recover().verdict, "empty")

    def test_an_experience_never_authorizes_execution(self):
        record = self._record(ExperienceLedger(self.path))
        self.assertFalse(record.execution_authorized)

    def test_a_tampered_ledger_supplies_no_lessons(self):
        """A rewritten ledger must not inject advice that was never earned."""
        ledger = ExperienceLedger(self.path)
        self._record(ledger)
        lines = self.path.read_text(encoding="utf-8").splitlines()
        lines[0] = lines[0].replace("failed", "verified")
        self.path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        self.assertEqual(ExperienceLedger(self.path).recall("fix-failing-pytest"), ())

    def test_no_history_is_not_a_verdict_about_the_task(self):
        standing = ExperienceLedger(self.path).standing("never-seen")
        self.assertEqual(standing.verdict, "no-evidence")
        self.assertEqual((standing.failures, standing.successes), (0, 0))

    def test_repeated_failures_stand_together(self):
        ledger = ExperienceLedger(self.path)
        self._record(ledger)
        self._record(ledger, run_id="run-2")
        standing = ledger.standing("fix-failing-pytest")
        self.assertEqual(standing.verdict, "consistent-failure")
        self.assertEqual(standing.failures, 2)

    def test_successes_stand_apart_from_failures(self):
        ledger = ExperienceLedger(self.path)
        self._record(ledger, verdict_result=_verified())
        standing = ledger.standing("fix-failing-pytest")
        self.assertEqual(standing.verdict, "consistent-success")
        self.assertEqual(standing.successes, 1)
    def test_a_later_success_contradicts_an_earlier_failure(self):
        """History that disagrees with itself must say so, not pick a side."""
        ledger = ExperienceLedger(self.path)
        self._record(ledger)
        self._record(ledger, run_id="run-2", verdict_result=_verified())
        standing = ledger.standing("fix-failing-pytest")
        self.assertEqual(standing.verdict, "contradicted")
        self.assertEqual((standing.failures, standing.successes), (1, 1))

    def test_standing_never_authorizes_execution(self):
        ledger = ExperienceLedger(self.path)
        self._record(ledger)
        self.assertFalse(ledger.standing("fix-failing-pytest").execution_authorized)

    def test_a_tampered_ledger_has_no_standing(self):
        ledger = ExperienceLedger(self.path)
        self._record(ledger)
        lines = self.path.read_text(encoding="utf-8").splitlines()
        lines[0] = lines[0].replace("failure", "success")
        self.path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        standing = ExperienceLedger(self.path).standing("fix-failing-pytest")
        self.assertEqual(standing.verdict, "unverifiable")

    def test_forecast_from_consistent_failure_is_likely_failure(self):
        ledger = ExperienceLedger(self.path)
        self._record(ledger)
        forecast = ledger.forecast("fix-failing-pytest")
        self.assertEqual(forecast.expectation, "likely-failure")
        self.assertEqual(len(forecast.based_on), 1)
        self.assertTrue(forecast.forecast_digest.startswith("sha256:"))

    def test_forecast_from_consistent_success_is_likely_success(self):
        ledger = ExperienceLedger(self.path)
        self._record(ledger, verdict_result=_verified())
        forecast = ledger.forecast("fix-failing-pytest")
        self.assertEqual(forecast.expectation, "likely-success")
        self.assertEqual(forecast.successes, 1)

    def test_forecast_reports_no_evidence_without_inventing_expectation(self):
        forecast = ExperienceLedger(self.path).forecast("never-seen")
        self.assertEqual(forecast.expectation, "no-evidence")
        self.assertEqual(forecast.based_on, ())

    def test_forecast_refuses_to_choose_for_contradicted_history(self):
        ledger = ExperienceLedger(self.path)
        self._record(ledger)
        self._record(ledger, run_id="run-2", verdict_result=_verified())
        forecast = ledger.forecast("fix-failing-pytest")
        self.assertEqual(forecast.expectation, "contradicted")
        self.assertEqual(forecast.based_on, (ledger.recall("fix-failing-pytest")[0].record_digest,
                                              ledger.recall("fix-failing-pytest")[1].record_digest))

    def test_forecast_on_tampered_history_is_unverifiable(self):
        ledger = ExperienceLedger(self.path)
        self._record(ledger)
        lines = self.path.read_text(encoding="utf-8").splitlines()
        lines[0] = lines[0].replace("failure", "success")
        self.path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        self.assertEqual(ledger.forecast("fix-failing-pytest").expectation, "unverifiable")

    def test_forecast_never_authorizes_execution(self):
        ledger = ExperienceLedger(self.path)
        self._record(ledger)
        self.assertFalse(ledger.forecast("fix-failing-pytest").execution_authorized)

    def test_settle_confirmed_when_forecast_matches_actual(self):
        ledger = ExperienceLedger(self.path)
        self._record(ledger)
        forecast = ledger.forecast("fix-failing-pytest")
        settlement = ledger.settle(
            forecast, actual_verdict="failed", run_id="run-2",
            run_digest="sha256:" + "d" * 64, event_head="sha256:" + "e" * 64
        )
        self.assertEqual(settlement.outcome, "confirmed")
        self.assertEqual(settlement.forecast_digest, forecast.forecast_digest)

    def test_settle_falsified_when_forecast_contradicts_actual(self):
        ledger = ExperienceLedger(self.path)
        self._record(ledger)
        forecast = ledger.forecast("fix-failing-pytest")
        settlement = ledger.settle(
            forecast, actual_verdict="verified", run_id="run-3",
            run_digest="sha256:" + "f" * 64, event_head="sha256:" + "g" * 64
        )
        self.assertEqual(settlement.outcome, "falsified")

    def test_settle_refuses_unknown_actual_verdict(self):
        ledger = ExperienceLedger(self.path)
        self._record(ledger)
        forecast = ledger.forecast("fix-failing-pytest")
        with self.assertRaises(ValueError):
            ledger.settle(
                forecast, actual_verdict="unknown", run_id="run-4",
                run_digest="sha256:" + "h" * 64, event_head="sha256:" + "i" * 64
            )
    def test_settle_stale_forecast_is_not_evaluable(self):
        """A forecast made before new evidence cannot be settled against it."""
        ledger = ExperienceLedger(self.path)
        self._record(ledger)
        old_forecast = ledger.forecast("fix-failing-pytest")
        self._record(ledger, run_id="run-new", verdict_result=_verified())
        settlement = ledger.settle(
            old_forecast, actual_verdict="verified", run_id="run-settle",
            run_digest="sha256:" + "j" * 64, event_head="sha256:" + "k" * 64
        )
        self.assertEqual(settlement.outcome, "not-evaluable")
        self.assertEqual(settlement.reason, "forecast-stale")

    def test_settle_same_run_twice_is_idempotent(self):
        ledger = ExperienceLedger(self.path)
        self._record(ledger)
        forecast = ledger.forecast("fix-failing-pytest")
        first = ledger.settle(
            forecast, actual_verdict="failed", run_id="run-5",
            run_digest="sha256:" + "m" * 64, event_head="sha256:" + "n" * 64
        )
        second = ledger.settle(
            forecast, actual_verdict="failed", run_id="run-5",
            run_digest="sha256:" + "m" * 64, event_head="sha256:" + "n" * 64
        )
        self.assertEqual(first.settlement_digest, second.settlement_digest)

    def test_settle_never_authorizes_execution(self):
        ledger = ExperienceLedger(self.path)
        self._record(ledger)
        forecast = ledger.forecast("fix-failing-pytest")
        settlement = ledger.settle(
            forecast, actual_verdict="failed", run_id="run-6",
            run_digest="sha256:" + "o" * 64, event_head="sha256:" + "p" * 64
        )
        self.assertFalse(settlement.execution_authorized)
