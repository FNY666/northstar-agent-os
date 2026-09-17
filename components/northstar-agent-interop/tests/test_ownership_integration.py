"""
Integration test: Ownership Ledger + Experience Ledger
Validates end-to-end ownership verification flow.
"""
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from experience_ledger import ExperienceLedger, OwnershipViolationError


class MockOwnershipLedger:
    """Mock OwnershipLedger for testing (duck typing)."""
    
    def __init__(self):
        self.valid_tokens = {}
    
    def validate_token(self, run_id: str, token: str) -> bool:
        """Validate if token matches the stored token for run_id."""
        return self.valid_tokens.get(run_id) == token


class OwnershipIntegrationTests(unittest.TestCase):
    """Integration tests for Ownership + Experience."""

    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.experience = ExperienceLedger(self.root / "experience.jsonl")
        self.ownership = MockOwnershipLedger()

    def tearDown(self):
        self.tempdir.cleanup()

    def test_end_to_end_with_valid_ownership(self):
        """E2E: acquire ownership → forecast → settle with valid token."""
        # Simulate ownership acquisition
        run_id = "run-001"
        token = "valid-token-001"
        self.ownership.valid_tokens[run_id] = token
        
        # Forecast
        fingerprint = "task-001"
        forecast = self.experience.forecast(fingerprint)
        
        # Settle with valid ownership
        self.experience.settle(
            forecast,
            actual_verdict="verified",
            run_id=run_id,
            fencing_token=token,
            ownership_ledger=self.ownership,
        )
        
        # Verify settlement recorded
        stats = self.experience.query_statistics(fingerprint)
        self.assertEqual(stats.total_runs, 1)
        self.assertEqual(stats.successes, 1)

    def test_end_to_end_rejects_invalid_ownership(self):
        """E2E: settle with invalid token → OwnershipViolationError."""
        # Simulate ownership acquisition
        run_id = "run-002"
        valid_token = "valid-token-002"
        invalid_token = "invalid-token-002"
        self.ownership.valid_tokens[run_id] = valid_token
        
        # Forecast
        fingerprint = "task-002"
        forecast = self.experience.forecast(fingerprint)
        
        # Settle with INVALID ownership
        with self.assertRaises(OwnershipViolationError):
            self.experience.settle(
                forecast,
                actual_verdict="verified",
                run_id=run_id,
                fencing_token=invalid_token,
                ownership_ledger=self.ownership,
            )
        
        # Verify NO settlement recorded (rejected)
        stats = self.experience.query_statistics(fingerprint)
        self.assertEqual(stats.total_runs, 0)

    def test_end_to_end_ownership_prevents_race(self):
        """E2E: two sessions compete, only valid owner can settle."""
        # Session 1 acquires ownership
        run_id = "run-003"
        token_session1 = "token-session-1"
        token_session2 = "token-session-2"
        self.ownership.valid_tokens[run_id] = token_session1
        
        fingerprint = "task-003"
        forecast = self.experience.forecast(fingerprint)
        
        # Session 1 settles successfully
        self.experience.settle(
            forecast,
            actual_verdict="verified",
            run_id=run_id,
            fencing_token=token_session1,
            ownership_ledger=self.ownership,
        )
        
        # Session 2 tries to settle with old/invalid token
        with self.assertRaises(OwnershipViolationError):
            self.experience.settle(
                forecast,
                actual_verdict="failed",
                run_id=run_id,
                fencing_token=token_session2,
                ownership_ledger=self.ownership,
            )
        
        # Only Session 1's settlement recorded
        stats = self.experience.query_statistics(fingerprint)
        self.assertEqual(stats.total_runs, 1)
        self.assertEqual(stats.successes, 1)  # Session 1's "verified"
        self.assertEqual(stats.failures, 0)   # Session 2 blocked


if __name__ == "__main__":
    unittest.main()
