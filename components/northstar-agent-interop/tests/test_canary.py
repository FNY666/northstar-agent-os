import sys
import tempfile
import unittest
from pathlib import Path

COMPONENT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(COMPONENT_ROOT))

from canary import CanaryOutcome, run_canary  # noqa: E402


class MultiBackendCanaryTests(unittest.TestCase):
    def test_claude_codex_hermes_chain_produces_independently_verified_result(self):
        with tempfile.TemporaryDirectory() as directory:
            outcome = run_canary(Path(directory))
        self.assertIsInstance(outcome, CanaryOutcome)
        self.assertEqual(outcome.status, "ok")
        self.assertTrue(outcome.verified)
        self.assertEqual(outcome.backend_ids, ("claude-code", "codex", "hermes"))
        self.assertEqual(outcome.receipt_statuses, ("finished", "finished", "finished"))
        self.assertEqual(outcome.verifier_verdicts, ("verified", "verified", "verified"))
        self.assertEqual(outcome.duplicate_side_effects, 0)
        self.assertEqual(outcome.handoff_count, 3)
        self.assertEqual(outcome.artifact_names, ("plan.json", "result.txt"))

    def test_codex_replay_is_idempotent_and_does_not_duplicate_side_effects(self):
        with tempfile.TemporaryDirectory() as directory:
            outcome = run_canary(Path(directory), replay_codex=True)
        self.assertEqual(outcome.status, "ok")
        self.assertEqual(outcome.codex_executor_calls, 1)
        self.assertEqual(outcome.duplicate_side_effects, 0)
        self.assertEqual(outcome.receipt_statuses, ("finished", "finished", "finished"))

    def test_independent_verifier_rejects_backend_claim_when_artifact_is_wrong(self):
        with tempfile.TemporaryDirectory() as directory:
            outcome = run_canary(Path(directory), tamper_result=True)
        self.assertEqual(outcome.status, "failed")
        self.assertFalse(outcome.verified)
        self.assertEqual(outcome.verifier_verdicts[-1], "verified")
        self.assertTrue(any("artifact" in error for error in outcome.errors))

    def test_review_unknown_never_becomes_success(self):
        with tempfile.TemporaryDirectory() as directory:
            outcome = run_canary(Path(directory), review_verdict="unknown")
        self.assertEqual(outcome.status, "unknown")
        self.assertFalse(outcome.verified)
        self.assertEqual(outcome.receipt_statuses[-1], "unknown")
        self.assertEqual(outcome.verifier_verdicts[-1], "unknown")

    def test_current_policy_revision_is_checked_before_each_handoff(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                run_canary(Path(directory), current_policy_revision="policy-revoked")

    def test_canary_rejects_invalid_options_without_creating_backend_work(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                run_canary(Path(directory), review_verdict="self-reported-success")
        self.assertTrue(True)


if __name__ == "__main__":
    unittest.main()
