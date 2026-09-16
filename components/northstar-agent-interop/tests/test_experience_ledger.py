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
