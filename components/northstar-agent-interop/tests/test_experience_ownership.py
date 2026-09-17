"""Ownership verification prevents non-owners from settling forecasts."""
import logging
import sys
import tempfile
import unittest
from pathlib import Path

COMPONENT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(COMPONENT_ROOT))
sys.path.insert(0, str(COMPONENT_ROOT.parent / "northstar-host"))
sys.path.insert(0, str(COMPONENT_ROOT.parent / "northstar-run-contract"))

from experience_ledger import (  # noqa: E402
    ExperienceLedger,
    OwnershipViolationError,
)


def _failed():
    return ("failed", ("completion test exited with code 1",), {})


def _verified():
    return ("verified", (), {"report.md": "sha256:" + "a" * 64})


class _OwningLedger:
    """Stub ownership ledger that always validates tokens."""

    def validate_token(self, run_id: str, token: str) -> bool:
        return True


class _RejectingLedger:
    """Stub ownership ledger that rejects every token."""

    def validate_token(self, run_id: str, token: str) -> bool:
        return False


class ExperienceOwnershipTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.path = Path(self.tempdir.name) / "experiences.jsonl"
        self.ledger = ExperienceLedger(self.path)
        # Seed one record so forecast has standing.
        self.ledger.record(
            verdict_result=_failed(),
            run_id="run-seed",
            run_digest="sha256:" + "b" * 64,
            fingerprint="fix-failing-pytest",
            event_head="sha256:" + "c" * 64,
        )
        self.forecast = self.ledger.forecast("fix-failing-pytest")

    def tearDown(self):
        self.tempdir.cleanup()

    # --- TDD tests ---

    def test_settle_with_valid_ownership(self):
        """Settlement proceeds when ownership ledger validates the token."""
        settlement = self.ledger.settle(
            self.forecast,
            actual_verdict="failed",
            run_id="run-own-1",
            run_digest="sha256:" + "d" * 64,
            event_head="sha256:" + "e" * 64,
            fencing_token="token-good",
            ownership_ledger=_OwningLedger(),
        )
        self.assertEqual(settlement.outcome, "confirmed")
        self.assertEqual(settlement.source_run_id, "run-own-1")

    def test_settle_rejects_invalid_ownership(self):
        """Settlement is refused when ownership ledger rejects the token."""
        with self.assertRaises(OwnershipViolationError):
            self.ledger.settle(
                self.forecast,
                actual_verdict="failed",
                run_id="run-bad-1",
                run_digest="sha256:" + "f" * 64,
                event_head="sha256:" + "g" * 64,
                fencing_token="token-bad",
                ownership_ledger=_RejectingLedger(),
            )

    def test_settle_backward_compatible_without_ownership(self):
        """Settlement still works when neither token nor ledger is provided."""
        settlement = self.ledger.settle(
            self.forecast,
            actual_verdict="failed",
            run_id="run-compat-1",
            run_digest="sha256:" + "h" * 64,
            event_head="sha256:" + "i" * 64,
        )
        self.assertEqual(settlement.outcome, "confirmed")

    def test_settle_logs_warning_when_ownership_not_verified(self):
        """A warning is logged when ownership parameters are omitted."""
        with self.assertLogs("experience_ledger", level="WARNING") as cm:
            self.ledger.settle(
                self.forecast,
                actual_verdict="failed",
                run_id="run-warn-1",
                run_digest="sha256:" + "j" * 64,
                event_head="sha256:" + "k" * 64,
            )
        self.assertTrue(any("ownership" in msg.lower() for msg in cm.output))

    def test_settle_partial_ownership_args_still_warns(self):
        """Providing only the token without a ledger still warns."""
        with self.assertLogs("experience_ledger", level="WARNING") as cm:
            self.ledger.settle(
                self.forecast,
                actual_verdict="failed",
                run_id="run-partial-1",
                run_digest="sha256:" + "l" * 64,
                event_head="sha256:" + "m" * 64,
                fencing_token="token-orphan",
            )
        self.assertTrue(any("ownership" in msg.lower() for msg in cm.output))

    def test_settle_without_token_but_with_ledger_warns(self):
        """Providing only the ledger without a token still warns."""
        with self.assertLogs("experience_ledger", level="WARNING") as cm:
            self.ledger.settle(
                self.forecast,
                actual_verdict="failed",
                run_id="run-partial-2",
                run_digest="sha256:" + "n" * 64,
                event_head="sha256:" + "o" * 64,
                ownership_ledger=_OwningLedger(),
            )
        self.assertTrue(any("ownership" in msg.lower() for msg in cm.output))


if __name__ == "__main__":
    unittest.main()
