"""Tests for the host-owned, non-authorizing continuation admission layer."""
import unittest

from autonomy_checkpoint import ContinuationVerdict, capture_checkpoint, verify_checkpoint
from continuation_admission import (
    ContinuationAdmission,
    ContinuationAdmissionError,
    ContinuationPolicy,
    evaluate_continuation_admission,
)


def inputs():
    return {
        "goal": {"objective": "continue safely", "scope": ["runtime"]},
        "session_id": "ns-admission",
        "runtime": {"permission_mode": "default", "tools": ["Read"]},
        "transcript": [{"role": "user", "content": "continue"}],
        "budget": {"max_budget_usd": 1.0, "total_cost_usd": 0.0},
    }


def pinned(observed_at=1000):
    source = inputs()
    checkpoint = capture_checkpoint(**source, observed_at=observed_at)
    verdict = verify_checkpoint(
        checkpoint, **source, now=observed_at + 10,
        expected_checkpoint_digest=checkpoint.checkpoint_digest,
    )
    return checkpoint, verdict


def unpinned(observed_at=1000):
    source = inputs()
    checkpoint = capture_checkpoint(**source, observed_at=observed_at)
    return checkpoint, verify_checkpoint(checkpoint, **source, now=observed_at + 10)


class ContinuationAdmissionTests(unittest.TestCase):
    def test_current_pinned_continuation_is_admissible_and_never_authorizing(self):
        checkpoint, verdict = pinned()
        admission = evaluate_continuation_admission(
            checkpoint, verdict, policy=ContinuationPolicy(max_age_seconds=60), now=1010
        )
        self.assertEqual(admission.state, "admit-continuation")
        self.assertEqual(admission.age_seconds, 10)
        self.assertEqual(admission.verdict_state, "current")
        self.assertEqual(admission.reasons, ())
        self.assertFalse(admission.execution_authorized)

    def test_an_old_but_matching_continuation_is_refused_by_freshness(self):
        checkpoint, verdict = pinned()
        admission = evaluate_continuation_admission(
            checkpoint, verdict, policy=ContinuationPolicy(max_age_seconds=5), now=1010
        )
        self.assertEqual(admission.state, "blocked-continuation-age")
        self.assertIn("continuation_expired", admission.reasons)
        self.assertEqual(admission.age_seconds, 10)
        self.assertFalse(admission.execution_authorized)

    def test_freshness_window_is_inclusive_at_the_boundary(self):
        checkpoint, verdict = pinned()
        admission = evaluate_continuation_admission(
            checkpoint, verdict, policy=ContinuationPolicy(max_age_seconds=10), now=1010
        )
        self.assertEqual(admission.state, "admit-continuation")

    def test_stale_and_unknown_verdicts_block_or_stay_unknown(self):
        source = inputs()
        checkpoint = capture_checkpoint(**source, observed_at=1000)
        source["transcript"] = [{"role": "user", "content": "drifted"}]
        drifted = verify_checkpoint(checkpoint, **source, now=1010)
        self.assertEqual(drifted.state, "stale")
        admission = evaluate_continuation_admission(
            checkpoint, drifted, policy=ContinuationPolicy(max_age_seconds=60), now=1010
        )
        self.assertEqual(admission.state, "blocked-continuation-stale")
        self.assertIn("transcript_changed", admission.reasons)
        unreadable = evaluate_continuation_admission(
            {"not": "a checkpoint"}, drifted, policy=ContinuationPolicy(max_age_seconds=60), now=1010
        )
        self.assertEqual(unreadable.state, "unknown")
        self.assertIn("checkpoint_unreadable", unreadable.reasons)
        absent = evaluate_continuation_admission(
            None, ContinuationVerdict("unknown", ("checkpoint_unrecorded",)),
            policy=ContinuationPolicy(max_age_seconds=60), now=1010,
        )
        self.assertEqual(absent.state, "unknown")
        self.assertIn("checkpoint_unrecorded", absent.reasons)

    def test_unpinned_continuation_requires_an_explicit_policy_opt_in(self):
        checkpoint, verdict = unpinned()
        self.assertEqual(verdict.state, "current-unpinned")
        strict = evaluate_continuation_admission(
            checkpoint, verdict, policy=ContinuationPolicy(max_age_seconds=60), now=1010
        )
        self.assertEqual(strict.state, "blocked-continuation-policy")
        self.assertIn("continuation_requires_pinned_checkpoint", strict.reasons)
        self.assertIn("checkpoint_digest_unpinned", strict.unresolved)
        relaxed = evaluate_continuation_admission(
            checkpoint, verdict,
            policy=ContinuationPolicy(max_age_seconds=60, require_pinned_checkpoint=False),
            now=1010,
        )
        self.assertEqual(relaxed.state, "admit-continuation-unpinned")
        self.assertIn("checkpoint_digest_unpinned", relaxed.unresolved)
        self.assertFalse(relaxed.execution_authorized)

    def test_an_observation_from_the_future_stays_unknown(self):
        checkpoint, verdict = pinned(observed_at=2000)
        admission = evaluate_continuation_admission(
            checkpoint, verdict, policy=ContinuationPolicy(max_age_seconds=60), now=1010
        )
        self.assertEqual(admission.state, "unknown")
        self.assertIn("observation_in_future", admission.reasons)
        self.assertIsNone(admission.age_seconds)

    def test_wire_round_trip_revalidates_and_refuses_claimed_authorization(self):
        checkpoint, verdict = pinned()
        admission = evaluate_continuation_admission(
            checkpoint, verdict, policy=ContinuationPolicy(max_age_seconds=60), now=1010
        )
        wire = admission.to_dict()
        self.assertEqual(ContinuationAdmission.from_dict(wire), admission)
        wire = admission.to_dict()
        wire["execution_authorized"] = True
        with self.assertRaises(ContinuationAdmissionError):
            ContinuationAdmission.from_dict(wire)
        wire = admission.to_dict()
        wire["state"] = "admit-anything"
        with self.assertRaises(ContinuationAdmissionError):
            ContinuationAdmission.from_dict(wire)

    def test_invalid_policies_and_authorizing_verdicts_are_refused(self):
        for bad in (-1, True, "60"):
            with self.assertRaises(ContinuationAdmissionError):
                ContinuationPolicy(max_age_seconds=bad)
        with self.assertRaises(ContinuationAdmissionError):
            ContinuationPolicy(max_age_seconds=60, require_pinned_checkpoint="yes")
        checkpoint, verdict = pinned()
        forged = type(verdict)(verdict.state, verdict.reasons, verdict.unverified, True)
        with self.assertRaises(ContinuationAdmissionError):
            evaluate_continuation_admission(
                checkpoint, forged, policy=ContinuationPolicy(max_age_seconds=60), now=1010
            )


class RuntimeContinuationAdmissionTests(unittest.TestCase):
    def _runtime(self, *, sessions=None):
        from loop import AgentRuntime, RuntimeConfig
        from providers.scripted import ScriptedProvider
        return AgentRuntime(
            provider=ScriptedProvider([]),
            config=RuntimeConfig(session_id="ns-admission", workspace=".", max_budget_usd=1.0),
            sessions=sessions,
        )

    def test_runtime_admits_a_pinned_fresh_persisted_continuation_without_resuming(self):
        import tempfile
        from pathlib import Path
        from autonomy_checkpoint_store import AutonomyCheckpointStore
        with tempfile.TemporaryDirectory() as root:
            runtime = self._runtime()
            store = AutonomyCheckpointStore(Path(root) / "continuations.jsonl")
            record = runtime.persist_continuation_checkpoint(
                store, goal={"objective": "continue safely"}, observed_at=1000
            )
            admission = runtime.admit_persisted_continuation_checkpoint(
                store, goal={"objective": "continue safely"}, now=1010,
                policy=ContinuationPolicy(max_age_seconds=60),
                expected_record_digest=record.record_digest,
            )
            self.assertEqual(admission.state, "admit-continuation")
            self.assertFalse(admission.execution_authorized)
            self.assertEqual(runtime.provider.requests, [])

    def test_runtime_refuses_an_expired_persisted_continuation(self):
        import tempfile
        from pathlib import Path
        from autonomy_checkpoint_store import AutonomyCheckpointStore
        with tempfile.TemporaryDirectory() as root:
            runtime = self._runtime()
            store = AutonomyCheckpointStore(Path(root) / "continuations.jsonl")
            runtime.persist_continuation_checkpoint(
                store, goal={"objective": "continue safely"}, observed_at=1000
            )
            admission = runtime.admit_persisted_continuation_checkpoint(
                store, goal={"objective": "continue safely"}, now=100000,
                policy=ContinuationPolicy(max_age_seconds=60),
            )
            self.assertEqual(admission.state, "blocked-continuation-age")
            self.assertIn("continuation_expired", admission.reasons)

    def test_runtime_reports_an_unrecorded_continuation_as_unknown(self):
        import tempfile
        from pathlib import Path
        from autonomy_checkpoint_store import AutonomyCheckpointStore
        with tempfile.TemporaryDirectory() as root:
            runtime = self._runtime()
            store = AutonomyCheckpointStore(Path(root) / "continuations.jsonl")
            admission = runtime.admit_persisted_continuation_checkpoint(
                store, goal={"objective": "continue safely"}, now=1010,
                policy=ContinuationPolicy(max_age_seconds=60),
            )
            self.assertEqual(admission.state, "unknown")
            self.assertIn("checkpoint_unrecorded", admission.reasons)

    def test_runtime_blocks_a_persisted_continuation_after_session_drift(self):
        import tempfile
        from pathlib import Path
        from autonomy_checkpoint_store import AutonomyCheckpointStore
        from sessions import SessionStore
        with tempfile.TemporaryDirectory() as root:
            sessions = SessionStore(root, session_id="ns-admission")
            runtime = self._runtime(sessions=sessions)
            store = AutonomyCheckpointStore(Path(root) / "continuations.jsonl")
            runtime.persist_continuation_checkpoint(
                store, goal={"objective": "continue safely"}, observed_at=1000
            )
            sessions.append("session_start", {"note": "drifted"})
            admission = runtime.admit_persisted_continuation_checkpoint(
                store, goal={"objective": "continue safely"}, now=1010,
                policy=ContinuationPolicy(max_age_seconds=60),
            )
            self.assertEqual(admission.state, "blocked-continuation-stale")
            self.assertIn("transcript_changed", admission.reasons)
            self.assertEqual(runtime.provider.requests, [])


if __name__ == "__main__":
    unittest.main()
