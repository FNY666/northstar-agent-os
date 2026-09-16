"""Tests for host-owned autonomous continuation checkpoints."""
import unittest

from autonomy_checkpoint import (
    AutonomyCheckpoint,
    AutonomyCheckpointError,
    capture_checkpoint,
)


def inputs():
    return {
        "goal": {"objective": "repair runtime safety", "scope": ["runtime"]},
        "session_id": "ns-checkpoint",
        "runtime": {"permission_mode": "default", "tools": ["Read", "Write"]},
        "transcript": [{"role": "user", "content": "continue"}],
        "budget": {"max_budget_usd": 1.0, "total_cost_usd": 0.1},
    }


class CheckpointContractTests(unittest.TestCase):
    def test_capture_is_deterministic_and_never_authorizes_execution(self):
        source = inputs()
        first = capture_checkpoint(**source, observed_at=1000)
        second = capture_checkpoint(**source, observed_at=1000)
        self.assertEqual(first, second)
        self.assertFalse(first.execution_authorized)
        self.assertTrue(first.checkpoint_digest.startswith("sha256:"))

    def test_wire_round_trip_is_exact(self):
        checkpoint = capture_checkpoint(**inputs(), observed_at=1000)
        self.assertEqual(AutonomyCheckpoint.from_dict(checkpoint.to_dict()), checkpoint)

    def test_tampered_digest_and_execution_authorization_are_refused(self):
        checkpoint = capture_checkpoint(**inputs(), observed_at=1000)
        wire = checkpoint.to_dict()
        wire["goal_digest"] = "sha256:" + "f" * 64
        with self.assertRaises(AutonomyCheckpointError):
            AutonomyCheckpoint.from_dict(wire)
        wire = checkpoint.to_dict()
        wire["execution_authorized"] = True
        with self.assertRaises(AutonomyCheckpointError):
            AutonomyCheckpoint.from_dict(wire)

    def test_invalid_host_owned_inputs_are_refused(self):
        source = inputs()
        source["goal"] = None
        with self.assertRaises(AutonomyCheckpointError):
            capture_checkpoint(**source, observed_at=1000)
        source = inputs()
        with self.assertRaises(AutonomyCheckpointError):
            capture_checkpoint(**source, observed_at=True)


if __name__ == "__main__":
    unittest.main()
