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


class ContinuationVerificationTests(unittest.TestCase):
    def setUp(self):
        self.source = inputs()
        self.checkpoint = capture_checkpoint(**self.source, observed_at=1000)

    def test_matching_observation_is_current_unpinned_and_never_authorizes(self):
        from autonomy_checkpoint import verify_checkpoint
        verdict = verify_checkpoint(self.checkpoint, **self.source, now=1010)
        self.assertEqual(verdict.state, "current-unpinned")
        self.assertIn("checkpoint_digest_unpinned", verdict.unverified)
        self.assertFalse(verdict.execution_authorized)

    def test_matching_external_pin_is_current(self):
        from autonomy_checkpoint import verify_checkpoint
        verdict = verify_checkpoint(
            self.checkpoint, **self.source, now=1010,
            expected_checkpoint_digest=self.checkpoint.checkpoint_digest,
        )
        self.assertEqual(verdict.state, "current")
        self.assertFalse(verdict.unverified)

    def test_each_host_owned_binding_can_make_a_checkpoint_stale(self):
        from autonomy_checkpoint import verify_checkpoint
        cases = {
            "goal": {"objective": "a different goal"},
            "runtime": {"permission_mode": "plan"},
            "transcript": [{"role": "user", "content": "tampered"}],
            "budget": {"max_budget_usd": 1.0, "total_cost_usd": 0.9},
        }
        for field, changed in cases.items():
            source = dict(self.source)
            source[field] = changed
            verdict = verify_checkpoint(self.checkpoint, **source, now=1010)
            self.assertEqual(verdict.state, "stale", field)
            self.assertIn(field + "_changed", verdict.reasons)
            self.assertFalse(verdict.execution_authorized)

    def test_bad_current_observation_is_unknown_not_a_crash(self):
        from autonomy_checkpoint import verify_checkpoint
        source = dict(self.source)
        source["budget"] = None
        verdict = verify_checkpoint(self.checkpoint, **source, now=1010)
        self.assertEqual(verdict.state, "unknown")
        self.assertIn("budget_unreadable", verdict.reasons)
        self.assertFalse(verdict.execution_authorized)

    def test_wrong_external_pin_is_refused(self):
        from autonomy_checkpoint import verify_checkpoint
        with self.assertRaises(AutonomyCheckpointError):
            verify_checkpoint(
                self.checkpoint, **self.source, now=1010,
                expected_checkpoint_digest="sha256:" + "f" * 64,
            )
