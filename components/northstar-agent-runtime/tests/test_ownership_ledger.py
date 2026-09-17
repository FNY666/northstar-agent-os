"""
Tests for OwnershipLedger — the "who owns this run" mechanism.

TDD RED phase: these tests define the expected behavior.
"""
import json
import os
import tempfile
import time
import unittest
from pathlib import Path

from ownership_ledger import (
    OwnershipLedger,
    OwnershipConflictError,
    OwnershipLostError,
    OwnershipViolationError,
    RunOwnership,
)


class TestOwnershipLedger(unittest.TestCase):
    """12 core tests for OwnershipLedger."""

    def setUp(self) -> None:
        self._tmpdir = tempfile.mkdtemp(prefix="ownership-test-")
        self.ledger_path = Path(self._tmpdir) / "ownerships.jsonl"
        self.ledger = OwnershipLedger(self.ledger_path)

    def tearDown(self) -> None:
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    # ── 1. Acquire new ownership ────────────────────────────────────────
    def test_acquire_new_ownership(self) -> None:
        """Fresh run → generation=1, fencing token is valid."""
        ownership = self.ledger.acquire("run-1", "owner-A", ttl=300)
        self.assertEqual(ownership.run_id, "run-1")
        self.assertEqual(ownership.owner_id, "owner-A")
        self.assertEqual(ownership.generation, 1)
        self.assertEqual(ownership.lease_ttl, 300)
        self.assertTrue(ownership.fencing_token)
        # Token should be reproducible
        self.assertEqual(ownership.fencing_token, ownership.computed_token())

    # ── 2. Acquire fails if lease still active ──────────────────────────
    def test_acquire_fails_if_lease_active(self) -> None:
        """Second acquire on same run while lease is active → ConflictError."""
        self.ledger.acquire("run-2", "owner-A", ttl=300)
        with self.assertRaises(OwnershipConflictError):
            self.ledger.acquire("run-2", "owner-B", ttl=300)

    # ── 3. Concurrent acquire uses CAS ──────────────────────────────────
    def test_concurrent_acquire_uses_cas(self) -> None:
        """Only one of two concurrent acquires succeeds (CAS semantics).

        Simulated by interleaving reads: the second acquire sees the first's
        generation and must refuse to overwrite.
        """
        # First acquirer succeeds
        owner_a = self.ledger.acquire("run-3", "owner-A", ttl=300)
        # Second acquirer should get ConflictError
        with self.assertRaises(OwnershipConflictError):
            self.ledger.acquire("run-3", "owner-B", ttl=300)
        # Verify original owner is still current
        current = self.ledger.query("run-3")
        self.assertIsNotNone(current)
        self.assertEqual(current.owner_id, "owner-A")
        self.assertEqual(current.generation, owner_a.generation)

    # ── 4. Renew requires valid token ───────────────────────────────────
    def test_renew_requires_valid_token(self) -> None:
        """Renewing with a forged/mismatched token → ViolationError."""
        ownership = self.ledger.acquire("run-4", "owner-A", ttl=300)
        bad = RunOwnership(
            run_id=ownership.run_id,
            generation=ownership.generation,
            owner_id="owner-A",
            acquired_at=ownership.acquired_at,
            lease_ttl=ownership.lease_ttl,
            fencing_token="deadbeef" * 8,
        )
        with self.assertRaises(OwnershipViolationError):
            self.ledger.renew(bad)

    # ── 5. Renew failure raises LostError ───────────────────────────────
    def test_renew_failure_raises_lost_error(self) -> None:
        """Renewing an expired lease → OwnershipLostError."""
        ownership = self.ledger.acquire("run-5", "owner-A", ttl=1)
        # Expire the lease
        time.sleep(1.1)
        with self.assertRaises(OwnershipLostError):
            self.ledger.renew(ownership)

    # ── 6. Generation increments on reacquire ───────────────────────────
    def test_generation_increments_on_reacquire(self) -> None:
        """After release, reacquire bumps generation to +1."""
        v1 = self.ledger.acquire("run-6", "owner-A", ttl=300)
        self.assertEqual(v1.generation, 1)
        self.ledger.release(v1)

        v2 = self.ledger.acquire("run-6", "owner-A", ttl=300)
        self.assertEqual(v2.generation, 2)

    # ── 7. Fencing rejects stale operations ─────────────────────────────
    def test_fencing_rejects_stale_operations(self) -> None:
        """A token from gen=1 is rejected after gen=2 has been acquired."""
        v1 = self.ledger.acquire("run-7", "owner-A", ttl=300)
        self.ledger.release(v1)
        v2 = self.ledger.acquire("run-7", "owner-B", ttl=300)

        # v1's token should no longer validate
        self.assertFalse(self.ledger.validate_token("run-7", v1.fencing_token))
        # v2's token should validate
        self.assertTrue(self.ledger.validate_token("run-7", v2.fencing_token))

    # ── 8. Query returns None if expired ────────────────────────────────
    def test_query_returns_none_if_expired(self) -> None:
        """Expired lease → query returns None."""
        self.ledger.acquire("run-8", "owner-A", ttl=1)
        time.sleep(1.1)
        self.assertIsNone(self.ledger.query("run-8"))

    # ── 9. mark_lost explicit state ─────────────────────────────────────
    def test_mark_lost_explicit_state(self) -> None:
        """mark_lost creates a terminal 'lost' entry that query returns."""
        self.ledger.acquire("run-9", "owner-A", ttl=300)
        self.ledger.mark_lost("run-9", reason="test_convergence")

        ownership = self.ledger.query("run-9")
        self.assertIsNotNone(ownership)
        self.assertEqual(ownership.state, "lost")
        self.assertEqual(ownership.lost_reason, "test_convergence")

    # ── 10. Release requires valid token ────────────────────────────────
    def test_release_requires_valid_token(self) -> None:
        """Releasing with invalid token → ViolationError."""
        ownership = self.ledger.acquire("run-10", "owner-A", ttl=300)
        bad = RunOwnership(
            run_id=ownership.run_id,
            generation=ownership.generation,
            owner_id="owner-A",
            acquired_at=ownership.acquired_at,
            lease_ttl=ownership.lease_ttl,
            fencing_token="invalid" * 8,
        )
        with self.assertRaises(OwnershipViolationError):
            self.ledger.release(bad)

    # ── 11. Digest chain detects corruption ─────────────────────────────
    def test_digest_chain_detects_corruption(self) -> None:
        """Manually corrupting a JSONL line → ledger refuses to load."""
        self.ledger.acquire("run-11", "owner-A", ttl=300)
        self.ledger.acquire("run-11b", "owner-B", ttl=300)

        # Corrupt the second line
        lines = self.ledger_path.read_text().splitlines(keepends=True)
        self.assertEqual(len(lines), 2)
        # Parse and tamper
        payload = json.loads(lines[1])
        payload["owner_id"] = "TAMPERED"
        lines[1] = json.dumps(payload) + "\n"
        self.ledger_path.write_text("".join(lines))

        ledger2 = OwnershipLedger(self.ledger_path)
        with self.assertRaises(OwnershipError):
            ledger2.list_all()

    # ── 12. list_all returns all ownerships ─────────────────────────────
    def test_list_all_returns_all_ownerships(self) -> None:
        """list_all returns every run's latest state (active + lost)."""
        o1 = self.ledger.acquire("run-12a", "owner-A", ttl=300)
        o2 = self.ledger.acquire("run-12b", "owner-B", ttl=300)
        self.ledger.mark_lost("run-12a", reason="crash")

        all_ownerships = self.ledger.list_all()
        by_run = {o.run_id: o for o in all_ownerships}
        self.assertIn("run-12a", by_run)
        self.assertIn("run-12b", by_run)
        self.assertEqual(by_run["run-12a"].state, "lost")
        self.assertEqual(by_run["run-12b"].owner_id, "owner-B")


# Import the base error for the corruption test
from ownership_ledger import OwnershipError


if __name__ == "__main__":
    unittest.main()
