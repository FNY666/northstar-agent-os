"""Tests for the host-owned, non-authorizing continuation admission layer."""
import unittest

from autonomy_checkpoint import ContinuationVerdict, capture_checkpoint, verify_checkpoint
from continuation_admission import (
    ContinuationAdmission,
    ContinuationAdmissionError,
    ContinuationAdmissionWitness,
    ContinuationPolicy,
    capture_admission_witness,
    evaluate_continuation_admission,
    verify_admission_witness,
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


def admit(*, max_age=60, now=1010, observed_at=1000):
    source = inputs()
    checkpoint = capture_checkpoint(**source, observed_at=observed_at)
    verdict = verify_checkpoint(
        checkpoint, **source, now=now, expected_checkpoint_digest=checkpoint.checkpoint_digest
    )
    return evaluate_continuation_admission(
        checkpoint, verdict, policy=ContinuationPolicy(max_age_seconds=max_age), now=now
    )


class ContinuationAdmissionDigestTests(unittest.TestCase):
    def test_every_decision_field_is_bound_into_the_admission_digest(self):
        base = admit()
        self.assertTrue(base.admission_digest.startswith("sha256:"))
        self.assertEqual(base.admission_digest, base.computed_digest)
        self.assertNotEqual(base.admission_digest, admit(max_age=61).admission_digest)
        self.assertNotEqual(base.admission_digest, admit(now=1011).admission_digest)
        self.assertNotEqual(base.admission_digest, admit(observed_at=999).admission_digest)
        expired = admit(max_age=1)
        self.assertEqual(expired.state, "blocked-continuation-age")
        self.assertNotEqual(base.admission_digest, expired.admission_digest)

    def test_wire_round_trip_revalidates_the_admission_digest(self):
        base = admit()
        self.assertEqual(ContinuationAdmission.from_dict(base.to_dict()), base)
        for field, value in (
            ("state", "admit-continuation-unpinned"),
            ("age_seconds", base.age_seconds + 1),
            ("policy_digest", "sha256:" + "0" * 64),
            ("checkpoint_digest", "sha256:" + "0" * 64),
            ("verdict_state", "stale"),
            ("admission_digest", "sha256:" + "0" * 64),
        ):
            tampered = base.to_dict()
            tampered[field] = value
            with self.assertRaises(ContinuationAdmissionError):
                ContinuationAdmission.from_dict(tampered)


class ContinuationAdmissionWitnessTests(unittest.TestCase):
    def test_matching_admission_and_pin_is_current(self):
        admission = admit()
        witness = capture_admission_witness(admission, observed_at=1010)
        verdict = verify_admission_witness(
            witness, admission, now=1011, expected_witness_digest=witness.witness_digest
        )
        self.assertEqual(verdict.state, "current")
        self.assertEqual(verdict.reasons, ())
        self.assertFalse(verdict.execution_authorized)

    def test_without_an_external_pin_the_witness_stays_unpinned(self):
        admission = admit()
        witness = capture_admission_witness(admission, observed_at=1010)
        verdict = verify_admission_witness(witness, admission, now=1011)
        self.assertEqual(verdict.state, "current-unpinned")
        self.assertIn("witness_digest_unpinned", verdict.unverified)
        self.assertFalse(verdict.execution_authorized)

    def test_a_replaced_admission_is_detected_even_when_it_is_self_consistent(self):
        admission = admit()
        witness = capture_admission_witness(admission, observed_at=1010)
        replaced = admit(max_age=1)
        self.assertEqual(replaced.state, "blocked-continuation-age")
        self.assertEqual(
            ContinuationAdmission.from_dict(replaced.to_dict()), replaced
        )
        verdict = verify_admission_witness(
            witness, replaced, now=1011, expected_witness_digest=witness.witness_digest
        )
        self.assertEqual(verdict.state, "stale")
        self.assertIn("admission_replaced", verdict.reasons)

    def test_a_replaced_witness_is_detected_against_an_external_pin(self):
        admission = admit()
        first = capture_admission_witness(admission, observed_at=1010)
        second = capture_admission_witness(admission, observed_at=1020)
        verdict = verify_admission_witness(
            second, admission, now=1021, expected_witness_digest=first.witness_digest
        )
        self.assertEqual(verdict.state, "stale")
        self.assertIn("witness_digest_changed", verdict.reasons)

    def test_a_future_observation_is_unknown(self):
        admission = admit()
        witness = capture_admission_witness(admission, observed_at=2000)
        verdict = verify_admission_witness(witness, admission, now=1011)
        self.assertEqual(verdict.state, "unknown")
        self.assertIn("observation_in_future", verdict.reasons)

    def test_unreadable_witness_or_admission_stays_unknown(self):
        admission = admit()
        witness = capture_admission_witness(admission, observed_at=1010)
        self.assertEqual(
            verify_admission_witness({"not": "a witness"}, admission, now=1011).state, "unknown"
        )
        self.assertEqual(
            verify_admission_witness(witness, {"not": "an admission"}, now=1011).state, "unknown"
        )
        tampered = witness.to_dict()
        tampered["admission_digest"] = "sha256:" + "0" * 64
        self.assertEqual(verify_admission_witness(tampered, admission, now=1011).state, "unknown")

    def test_witness_wire_round_trip_revalidates_its_own_digest(self):
        witness = capture_admission_witness(admit(), observed_at=1010)
        self.assertEqual(ContinuationAdmissionWitness.from_dict(witness.to_dict()), witness)
        tampered = witness.to_dict()
        tampered["witness_digest"] = "sha256:" + "0" * 64
        with self.assertRaises(ContinuationAdmissionError):
            ContinuationAdmissionWitness.from_dict(tampered)


class ObjectiveContinuityEvaluationTests(unittest.TestCase):
    def _pinned(self, *, observed_at=1000, now=1010):
        source = inputs()
        checkpoint = capture_checkpoint(**source, observed_at=observed_at)
        verdict = verify_checkpoint(
            checkpoint, **source, now=now, expected_checkpoint_digest=checkpoint.checkpoint_digest
        )
        return checkpoint, verdict

    def test_a_changed_objective_blocks_under_the_default_policy(self):
        checkpoint, verdict = self._pinned()
        admission = evaluate_continuation_admission(
            checkpoint, verdict, policy=ContinuationPolicy(max_age_seconds=60), now=1010,
            objective_changed_at_sequence=2,
        )
        self.assertEqual(admission.state, "blocked-continuation-objective")
        self.assertIn("continuation_objective_changed", admission.reasons)
        self.assertEqual(admission.objective_changed_at_sequence, 2)
        self.assertFalse(admission.execution_authorized)

    def test_an_invalid_objective_sequence_is_rejected(self):
        checkpoint, verdict = self._pinned()
        for bad in (0, True, "2"):
            with self.assertRaises(ContinuationAdmissionError):
                evaluate_continuation_admission(
                    checkpoint, verdict, policy=ContinuationPolicy(max_age_seconds=60), now=1010,
                    objective_changed_at_sequence=bad,
                )


class RuntimeObjectiveAdmissionTests(unittest.TestCase):
    def _runtime(self, *, sessions=None):
        from loop import AgentRuntime, RuntimeConfig
        from providers.scripted import ScriptedProvider
        return AgentRuntime(
            provider=ScriptedProvider([]),
            config=RuntimeConfig(session_id="ns-objective", workspace=".", max_budget_usd=1.0),
            sessions=sessions,
        )

    def _store_with(self, root, goals):
        from pathlib import Path
        from autonomy_checkpoint_store import AutonomyCheckpointStore
        from sessions import SessionStore
        runtime = self._runtime(sessions=SessionStore(root, session_id="ns-objective"))
        store = AutonomyCheckpointStore(Path(root) / "objective.jsonl")
        last = None
        for index, goal in enumerate(goals):
            last = runtime.persist_continuation_checkpoint(
                store, goal={"objective": goal}, observed_at=1000 + index
            )
        return runtime, store, last.record_digest

    def test_a_swapped_objective_is_refused_by_default(self):
        import tempfile
        with tempfile.TemporaryDirectory() as root:
            runtime, store, digest = self._store_with(root, ["first", "second"])
            admission = runtime.admit_persisted_continuation_checkpoint(
                store, goal={"objective": "second"}, now=1010,
                policy=ContinuationPolicy(max_age_seconds=60),
                expected_record_digest=digest,
            )
            self.assertEqual(admission.state, "blocked-continuation-objective")
            self.assertIn("continuation_objective_changed", admission.reasons)
            self.assertEqual(admission.objective_changed_at_sequence, 2)
            self.assertFalse(admission.execution_authorized)
            self.assertEqual(runtime.provider.requests, [])

    def test_the_host_can_opt_out_of_objective_continuity(self):
        import tempfile
        with tempfile.TemporaryDirectory() as root:
            runtime, store, digest = self._store_with(root, ["first", "second"])
            admission = runtime.admit_persisted_continuation_checkpoint(
                store, goal={"objective": "second"}, now=1010,
                policy=ContinuationPolicy(max_age_seconds=60, require_objective_continuity=False),
                expected_record_digest=digest,
            )
            self.assertEqual(admission.state, "admit-continuation")
            self.assertEqual(admission.objective_changed_at_sequence, 2)
            self.assertFalse(admission.execution_authorized)

    def test_a_continuous_chain_is_unaffected(self):
        import tempfile
        with tempfile.TemporaryDirectory() as root:
            runtime, store, digest = self._store_with(root, ["steady", "steady"])
            admission = runtime.admit_persisted_continuation_checkpoint(
                store, goal={"objective": "steady"}, now=1010,
                policy=ContinuationPolicy(max_age_seconds=60),
                expected_record_digest=digest,
            )
            self.assertEqual(admission.state, "admit-continuation")
            self.assertIsNone(admission.objective_changed_at_sequence)

    def test_a_tampered_chain_fails_closed(self):
        import json
        import tempfile
        with tempfile.TemporaryDirectory() as root:
            runtime, store, digest = self._store_with(root, ["steady"])
            row = json.loads(store.path.read_text(encoding="utf-8").splitlines()[0])
            row["record_digest"] = "sha256:" + "e" * 64
            store.path.write_text(json.dumps(row) + "\n", encoding="utf-8")
            admission = runtime.admit_persisted_continuation_checkpoint(
                store, goal={"objective": "steady"}, now=1010,
                policy=ContinuationPolicy(max_age_seconds=60),
            )
            self.assertEqual(admission.state, "unknown")
            self.assertFalse(admission.execution_authorized)

    def test_policy_wire_form_requires_the_objective_flag(self):
        wire = ContinuationPolicy(max_age_seconds=60).to_dict()
        self.assertTrue(wire["require_objective_continuity"])
        without = dict(wire)
        without.pop("require_objective_continuity")
        with self.assertRaises(ContinuationAdmissionError):
            ContinuationPolicy.from_dict(without)
        flipped = dict(wire)
        flipped["require_objective_continuity"] = "yes"
        with self.assertRaises(ContinuationAdmissionError):
            ContinuationPolicy.from_dict(flipped)


if __name__ == "__main__":
    unittest.main()
