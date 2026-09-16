"""Durable, non-authorizing continuation checkpoint records."""
import json
import tempfile
import unittest
from pathlib import Path

from autonomy_checkpoint import capture_checkpoint
from autonomy_checkpoint_store import AutonomyCheckpointStore


def checkpoint(session_id="ns-store", goal="continue"):
    return capture_checkpoint(
        goal={"objective": goal}, session_id=session_id,
        runtime={"permission_mode": "default"}, transcript=[],
        budget={"max_budget_usd": 1.0, "total_cost_usd": 0.0}, observed_at=1000,
    )


class AutonomyCheckpointStoreTests(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.TemporaryDirectory()
        self.addCleanup(self.root.cleanup)
        self.path = Path(self.root.name) / "continuations.jsonl"
        self.store = AutonomyCheckpointStore(self.path)

    def test_append_restores_after_reopen_with_a_pinned_head(self):
        record = self.store.append(checkpoint())
        reopened = AutonomyCheckpointStore(self.path)
        resolution = reopened.resolve("ns-store", expected_record_digest=record.record_digest)
        self.assertEqual(resolution.state, "recorded")
        self.assertEqual(resolution.record, record)
        self.assertFalse(resolution.execution_authorized)

    def test_missing_external_pin_is_explicit(self):
        self.store.append(checkpoint())
        resolution = self.store.resolve("ns-store")
        self.assertEqual(resolution.state, "recorded-unpinned")
        self.assertIn("record_digest_unpinned", resolution.unverified)

    def test_independent_store_instances_keep_sequences_contiguous(self):
        first = self.store.append(checkpoint(goal="one"))
        second = AutonomyCheckpointStore(self.path).append(checkpoint(goal="two"))
        self.assertEqual((first.sequence, second.sequence), (1, 2))
        self.assertEqual(second.prev_record_digest, first.record_digest)

    def test_record_tampering_is_unverifiable(self):
        self.store.append(checkpoint())
        row = json.loads(self.path.read_text(encoding="utf-8").splitlines()[0])
        row["checkpoint"]["goal_digest"] = "sha256:" + "f" * 64
        self.path.write_text(json.dumps(row) + "\n", encoding="utf-8")
        resolution = self.store.resolve("ns-store")
        self.assertEqual(resolution.state, "unverifiable")
        self.assertFalse(resolution.execution_authorized)

    def test_record_digest_tampering_is_unverifiable(self):
        self.store.append(checkpoint())
        row = json.loads(self.path.read_text(encoding="utf-8").splitlines()[0])
        row["record_digest"] = "sha256:" + "e" * 64
        self.path.write_text(json.dumps(row) + "\n", encoding="utf-8")
        self.assertEqual(self.store.resolve("ns-store").state, "unverifiable")

    def test_tail_truncation_is_detected_against_head_witness(self):
        self.store.append(checkpoint(goal="one"))
        self.store.append(checkpoint(goal="two"))
        lines = self.path.read_text(encoding="utf-8").splitlines(True)
        self.path.write_text(lines[0], encoding="utf-8")
        resolution = self.store.resolve("ns-store")
        self.assertEqual(resolution.state, "unverifiable")

    def test_unknown_session_is_unrecorded(self):
        self.store.append(checkpoint())
        self.assertEqual(self.store.resolve("ns-other").state, "unrecorded")


if __name__ == "__main__":
    unittest.main()
