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

class AgentRuntimeAdapterTests(unittest.TestCase):
    def _runtime(self, *, sessions=None):
        from loop import AgentRuntime, RuntimeConfig
        from providers.scripted import ScriptedProvider
        return AgentRuntime(
            provider=ScriptedProvider([]),
            config=RuntimeConfig(session_id="ns-adapter", workspace=".", max_budget_usd=1.0),
            sessions=sessions,
        )

    def test_runtime_captures_and_verifies_its_host_owned_state(self):
        runtime = self._runtime()
        checkpoint = runtime.capture_continuation_checkpoint(
            goal={"objective": "continue safely"}, observed_at=1000
        )
        verdict = runtime.verify_continuation_checkpoint(
            checkpoint, goal={"objective": "continue safely"}, now=1010,
            expected_checkpoint_digest=checkpoint.checkpoint_digest,
        )
        self.assertEqual(verdict.state, "current")
        self.assertFalse(verdict.execution_authorized)

    def test_runtime_detects_a_transcript_change_without_resuming(self):
        from sessions import SessionStore
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as root:
            store = SessionStore(root, session_id="ns-adapter")
            runtime = self._runtime(sessions=store)
            checkpoint = runtime.capture_continuation_checkpoint(goal={"objective": "x"}, observed_at=1000)
            store.append("session_start", {"note": "new host record"})
            verdict = runtime.verify_continuation_checkpoint(checkpoint, goal={"objective": "x"}, now=1010)
            self.assertEqual(verdict.state, "stale")
            self.assertIn("transcript_changed", verdict.reasons)

    def test_runtime_detects_governance_surface_drift(self):
        runtime = self._runtime()
        checkpoint = runtime.capture_continuation_checkpoint(goal={"objective": "x"}, observed_at=1000)
        runtime.tools.unregister("Write")
        verdict = runtime.verify_continuation_checkpoint(checkpoint, goal={"objective": "x"}, now=1010)
        self.assertEqual(verdict.state, "stale")
        self.assertIn("runtime_changed", verdict.reasons)

    def test_runtime_persists_and_recovers_a_pinned_continuation(self):
        import tempfile
        from pathlib import Path
        from autonomy_checkpoint_store import AutonomyCheckpointStore
        from sessions import SessionStore
        with tempfile.TemporaryDirectory() as root:
            sessions = SessionStore(root, session_id="ns-adapter")
            runtime = self._runtime(sessions=sessions)
            store = AutonomyCheckpointStore(Path(root) / "continuations.jsonl")
            record = runtime.persist_continuation_checkpoint(
                store, goal={"objective": "persist"}, observed_at=1000
            )
            restored = self._runtime(sessions=SessionStore(root, session_id="ns-adapter"))
            verdict = restored.resolve_persisted_continuation_checkpoint(
                store, goal={"objective": "persist"}, now=1010,
                expected_record_digest=record.record_digest,
            )
            self.assertEqual(verdict.state, "current")
            self.assertFalse(verdict.execution_authorized)
            self.assertEqual(restored.provider.requests, [])

    def test_runtime_persisted_checkpoint_detects_session_drift_without_resuming(self):
        import tempfile
        from pathlib import Path
        from autonomy_checkpoint_store import AutonomyCheckpointStore
        from sessions import SessionStore
        with tempfile.TemporaryDirectory() as root:
            sessions = SessionStore(root, session_id="ns-adapter")
            runtime = self._runtime(sessions=sessions)
            store = AutonomyCheckpointStore(Path(root) / "continuations.jsonl")
            runtime.persist_continuation_checkpoint(store, goal={"objective": "persist"}, observed_at=1000)
            sessions.append("session_start", {"note": "changed"})
            verdict = runtime.resolve_persisted_continuation_checkpoint(
                store, goal={"objective": "persist"}, now=1010
            )
            self.assertEqual(verdict.state, "stale")
            self.assertIn("transcript_changed", verdict.reasons)

    def test_runtime_treats_a_tampered_store_as_unknown(self):
        import tempfile
        from pathlib import Path
        import json
        from autonomy_checkpoint_store import AutonomyCheckpointStore
        with tempfile.TemporaryDirectory() as root:
            runtime = self._runtime()
            store = AutonomyCheckpointStore(Path(root) / "continuations.jsonl")
            runtime.persist_continuation_checkpoint(store, goal={"objective": "persist"}, observed_at=1000)
            row = json.loads(store.path.read_text(encoding="utf-8").splitlines()[0])
            row["record_digest"] = "sha256:" + "f" * 64
            store.path.write_text(json.dumps(row) + "\n", encoding="utf-8")
            verdict = runtime.resolve_persisted_continuation_checkpoint(
                store, goal={"objective": "persist"}, now=1010
            )
            self.assertEqual(verdict.state, "unknown")
            self.assertFalse(verdict.execution_authorized)
