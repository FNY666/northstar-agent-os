"""Tests for the stale-checkpoint gate: a checkpoint carries the external
world's checksum, and recovery checks it.

The rules under test, one class each:

* creation is fail closed -- no checksum, no freshness sequence, no checkpoint;
* the checksum is canonical -- the same state spelled two ways hashes the
  same, and a state that cannot be canonicalised is refused;
* the verdict is three states, never a boolean;
* the three real paths are driven end to end: a clean recovery, a drifted
  recovery, and the dirty-recovery drill.
"""

from __future__ import annotations

import json
import unittest

from stale_checkpoint_gate import (
    CHECKSUM_PREFIX,
    Checkpoint,
    ExternalWorld,
    GateVerdict,
    GateVerdictStatus,
    InvalidChecksumError,
    InvalidFreshnessSeqError,
    MissingExternalStateError,
    StaleCheckpointGate,
    StaleCheckpointGateError,
    UncanonicalizableStateError,
    WorldWrite,
    canonicalize,
    checksum_of_state,
    dirty_recovery_drill,
    drill,
    external_checksum,
    is_checksum,
)


class _Schema:
    """The external world this suite watches: a schema version and a task list.

    The schema version is the thing the source's example talks about: an
    agent that resumes holding an old schema belief and keeps going,
    confidently, on a world that has moved on.
    """

    V3 = {"schema": "v3", "tasks": []}
    V2 = {"schema": "v2", "tasks": []}


class CanonicalChecksumTests(unittest.TestCase):
    """The checksum is canonical, and refuses what it cannot describe."""

    def test_same_state_spelled_two_ways_hashes_the_same(self):
        # Key order must not matter: the same external state, written in a
        # different order, is the same external state.
        first = {"schema": "v3", "tasks": [], "cursor": 12}
        second = {"cursor": 12, "tasks": [], "schema": "v3"}
        self.assertEqual(checksum_of_state(first), checksum_of_state(second))

    def test_nested_key_order_does_not_change_the_checksum(self):
        first = {"outer": {"b": 1, "a": {"y": 2, "x": 3}}}
        second = {"outer": {"a": {"x": 3, "y": 2}, "b": 1}}
        self.assertEqual(checksum_of_state(first), checksum_of_state(second))

    def test_checksum_has_the_fixed_sha256_shape(self):
        digest = checksum_of_state(_Schema.V3)
        self.assertTrue(digest.startswith(CHECKSUM_PREFIX))
        self.assertTrue(is_checksum(digest))
        self.assertEqual(len(digest), len(CHECKSUM_PREFIX) + 64)
        self.assertEqual(digest, digest.lower())

    def test_canonical_form_is_sorted_and_compact(self):
        canonical = canonicalize({"b": 1, "a": 2})
        self.assertEqual(canonical, '{"a":2,"b":1}')
        self.assertNotIn(", ", canonical)
        self.assertNotIn(": ", canonical)

    def test_different_states_hash_differently(self):
        self.assertNotEqual(checksum_of_state(_Schema.V3), checksum_of_state(_Schema.V2))

    def test_uncanonicalizable_state_is_refused_not_fuzzily_hashed(self):
        # NaN has no JSON spelling; a fuzzy hash of it would be a hash of
        # nothing.
        with self.assertRaises(UncanonicalizableStateError):
            checksum_of_state({"value": float("nan")})
        with self.assertRaises(UncanonicalizableStateError):
            checksum_of_state({"value": float("inf")})

    def test_non_string_dict_keys_are_refused(self):
        # json.dumps coerces {1: "a"} to {"1": "a"}; two different external
        # states must not share a checksum, so the ambiguity is refused.
        with self.assertRaises(UncanonicalizableStateError):
            checksum_of_state({1: "a"})

    def test_arbitrary_objects_are_refused(self):
        class Opaque:
            pass

        with self.assertRaises(UncanonicalizableStateError):
            checksum_of_state({"handle": Opaque()})

    def test_malformed_checksum_is_not_accepted(self):
        self.assertFalse(is_checksum("sha256:zzz"))
        self.assertFalse(is_checksum(""))
        self.assertFalse(is_checksum(None))
        self.assertFalse(is_checksum("md5:" + "0" * 32))


class FailClosedCreationTests(unittest.TestCase):
    """A checkpoint that cannot say what the world looked like is never created."""

    def setUp(self):
        self.gate = StaleCheckpointGate()

    def test_creation_without_a_checksum_is_refused(self):
        with self.assertRaises(MissingExternalStateError):
            self.gate.create("ck-no-checksum", freshness_seq=3)

    def test_creation_with_a_malformed_checksum_is_refused(self):
        with self.assertRaises(MissingExternalStateError):
            self.gate.create("ck-bad", external_checksum="not-a-checksum", freshness_seq=3)

    def test_creation_without_a_freshness_sequence_is_refused(self):
        # freshness_seq has no default: it must be given.
        with self.assertRaises(TypeError):
            self.gate.create("ck-no-seq", external_state=_Schema.V3)

    def test_creation_with_a_negative_freshness_sequence_is_refused(self):
        with self.assertRaises(InvalidFreshnessSeqError):
            self.gate.create("ck-negative", external_state=_Schema.V3, freshness_seq=-1)

    def test_creation_with_a_non_integer_freshness_sequence_is_refused(self):
        with self.assertRaises(InvalidFreshnessSeqError):
            self.gate.create("ck-float", external_state=_Schema.V3, freshness_seq=1.5)

    def test_creation_with_both_a_state_and_a_checksum_is_refused(self):
        with self.assertRaises(MissingExternalStateError):
            self.gate.create(
                "ck-both",
                external_state=_Schema.V3,
                external_checksum=checksum_of_state(_Schema.V3),
                freshness_seq=3,
            )

    def test_created_checkpoint_carries_the_whole_witness(self):
        checkpoint = self.gate.create("ck-1", external_state=_Schema.V3, freshness_seq=7)
        self.assertIsInstance(checkpoint, Checkpoint)
        self.assertEqual(checkpoint.external_checksum, checksum_of_state(_Schema.V3))
        self.assertEqual(checkpoint.freshness_seq, 7)
        self.assertEqual(checkpoint.created_seq, 7)
        self.assertEqual(checkpoint.witness.external_checksum, checkpoint.external_checksum)

    def test_created_seq_is_recorded_separately_from_the_freshness_sequence(self):
        checkpoint = self.gate.create(
            "ck-2", external_state=_Schema.V3, freshness_seq=7, created_seq=9
        )
        self.assertEqual(checkpoint.freshness_seq, 7)
        self.assertEqual(checkpoint.created_seq, 9)


class VerdictShapeTests(unittest.TestCase):
    """The verdict is three explicit states, never a boolean."""

    def setUp(self):
        self.gate = StaleCheckpointGate()
        self.checkpoint = self.gate.create("ck-1", external_state=_Schema.V3, freshness_seq=7)

    def test_the_status_is_one_of_three_named_states(self):
        statuses = {
            GateVerdictStatus.PASS,
            GateVerdictStatus.FLAGGED,
            GateVerdictStatus.REJECTED,
        }
        self.assertEqual(len(statuses), 3)
        self.assertEqual(
            {item.value for item in statuses},
            {"pass", "flagged", "rejected"},
        )

    def test_a_verdict_is_not_a_boolean(self):
        verdict = self.gate.verify(self.checkpoint, checksum_of_state(_Schema.V3), 7)
        self.assertIsNot(verdict, True)
        self.assertIsNot(verdict, False)
        self.assertIsInstance(verdict, GateVerdict)
        self.assertIsInstance(verdict.status, GateVerdictStatus)

    def test_pass_and_flagged_are_recoverable_but_rejected_is_not(self):
        clean = self.gate.verify(self.checkpoint, checksum_of_state(_Schema.V3), 7)
        flagged = self.gate.verify(self.checkpoint, checksum_of_state(_Schema.V3), 9)
        rejected = self.gate.verify(self.checkpoint, checksum_of_state(_Schema.V2), 9)
        self.assertTrue(clean.recoverable)
        self.assertTrue(flagged.recoverable)
        self.assertFalse(rejected.recoverable)
        self.assertTrue(clean.passed)
        self.assertFalse(flagged.passed)
        self.assertFalse(rejected.passed)

    def test_a_malformed_live_checksum_is_a_programming_error_not_a_verdict(self):
        with self.assertRaises(InvalidChecksumError):
            self.gate.verify(self.checkpoint, "sha256:nope", 7)

    def test_a_malformed_live_sequence_is_refused(self):
        with self.assertRaises(InvalidFreshnessSeqError):
            self.gate.verify(self.checkpoint, checksum_of_state(_Schema.V3), "seven")


class CleanRecoveryPathTests(unittest.TestCase):
    """Path (a): the world is as the checkpoint remembers it -- recovery proceeds."""

    def setUp(self):
        self.gate = StaleCheckpointGate()
        self.checkpoint = self.gate.create(
            "ck-clean",
            external_state=_Schema.V3,
            freshness_seq=7,
            session_id="s-1",
            turns=14,
        )

    def test_a_clean_recovery_passes_and_the_recovery_proceeds(self):
        live = _Schema.V3
        verdict = self.gate.verify(self.checkpoint, checksum_of_state(live), 7)
        self.assertIs(verdict.status, GateVerdictStatus.PASS)
        self.assertTrue(verdict.recoverable)
        self.assertEqual(verdict.seq_advance, 0)
        self.assertIsNone(verdict.drift)
        # The checkpoint's counters are what the recovery inherits.
        self.assertEqual(self.checkpoint.turns, 14)

    def test_the_pass_verdict_states_the_evidence_it_saw(self):
        verdict = self.gate.verify(
            self.checkpoint, checksum_of_state(_Schema.V3), 7
        )
        self.assertEqual(verdict.expected_checksum, checksum_of_state(_Schema.V3))
        self.assertEqual(verdict.actual_checksum, verdict.expected_checksum)
        self.assertEqual(verdict.expected_seq, 7)
        self.assertEqual(verdict.actual_seq, 7)
        self.assertIn("matches", verdict.reason)

    def test_the_witnessed_world_is_the_same_world_the_checkpoint_recorded(self):
        world = ExternalWorld(state=dict(_Schema.V3), seq=7)
        self.assertEqual(world.checksum, self.checkpoint.external_checksum)
        verdict = self.gate.verify(self.checkpoint, world.checksum, world.seq)
        self.assertIs(verdict.status, GateVerdictStatus.PASS)


class DriftedRecoveryPathTests(unittest.TestCase):
    """Path (b): the world contradicts the checkpoint -- the recovery is refused."""

    def setUp(self):
        self.gate = StaleCheckpointGate()
        # The checkpoint holds the old schema (the source's "step 14" case).
        self.checkpoint = self.gate.create(
            "ck-old-schema",
            external_state=_Schema.V2,
            freshness_seq=14,
            turns=14,
        )

    def test_a_drifted_recovery_is_rejected_and_does_not_proceed(self):
        live = _Schema.V3  # the world moved on: the schema is now v3
        verdict = self.gate.verify(self.checkpoint, checksum_of_state(live), 15)
        self.assertIs(verdict.status, GateVerdictStatus.REJECTED)
        self.assertFalse(verdict.recoverable)

    def test_the_rejection_carries_the_expected_and_the_actual_checksum(self):
        live = _Schema.V3
        verdict = self.gate.verify(self.checkpoint, checksum_of_state(live), 15)
        self.assertEqual(verdict.expected_checksum, checksum_of_state(_Schema.V2))
        self.assertEqual(verdict.actual_checksum, checksum_of_state(_Schema.V3))
        self.assertNotEqual(verdict.expected_checksum, verdict.actual_checksum)

    def test_the_rejection_states_the_drift(self):
        verdict = self.gate.verify(
            self.checkpoint, checksum_of_state(_Schema.V3), 15
        )
        self.assertIsNotNone(verdict.drift)
        self.assertIn(checksum_of_state(_Schema.V2), verdict.drift)
        self.assertIn(checksum_of_state(_Schema.V3), verdict.drift)
        self.assertIn("stale", verdict.reason)

    def test_the_drift_is_caught_even_when_the_sequence_did_not_move(self):
        # The world changed without advancing its sequence: the checksum is
        # the only witness that can see it.
        verdict = self.gate.verify(
            self.checkpoint, checksum_of_state(_Schema.V3), 14
        )
        self.assertIs(verdict.status, GateVerdictStatus.REJECTED)


class FlaggedWorldAdvancedTests(unittest.TestCase):
    """The world advanced: recoverable, but the movement must be declared."""

    def setUp(self):
        self.gate = StaleCheckpointGate()
        self.checkpoint = self.gate.create(
            "ck-advanced", external_state=_Schema.V3, freshness_seq=7
        )

    def test_a_advanced_world_is_flagged_not_passed(self):
        verdict = self.gate.verify(
            self.checkpoint, checksum_of_state(_Schema.V3), 12
        )
        self.assertIs(verdict.status, GateVerdictStatus.FLAGGED)
        self.assertTrue(verdict.recoverable)
        self.assertFalse(verdict.passed)

    def test_the_flag_carries_how_far_the_world_moved(self):
        verdict = self.gate.verify(
            self.checkpoint, checksum_of_state(_Schema.V3), 12
        )
        self.assertEqual(verdict.seq_advance, 5)
        self.assertIn("5", verdict.reason)

    def test_a_backwards_sequence_is_rejected_with_a_reason(self):
        verdict = self.gate.verify(
            self.checkpoint, checksum_of_state(_Schema.V3), 3
        )
        self.assertIs(verdict.status, GateVerdictStatus.REJECTED)
        self.assertFalse(verdict.recoverable)
        self.assertIn("backwards", verdict.reason)
        self.assertEqual(verdict.seq_advance, 0)

    def test_a_backwards_sequence_is_rejected_even_with_a_matching_checksum(self):
        # The dangerous case: the checksum matches, so a checksum-only gate
        # would wave this through.
        verdict = self.gate.verify(
            self.checkpoint, checksum_of_state(_Schema.V3), 6
        )
        self.assertIs(verdict.status, GateVerdictStatus.REJECTED)
        self.assertIn("backwards", verdict.reason)


class DirtyRecoveryDrillTests(unittest.TestCase):
    """Path (c): revert from a point with later writes and real drift.

    The source asks for the *dirty* case: not the clean immediate
    rollback, but a revert from a point that has since been written to.
    """

    def setUp(self):
        self.gate = StaleCheckpointGate()

    def test_a_drill_over_a_written_world_flags_the_drift_and_does_not_silently_pass(self):
        # The world keeps its schema but gains a task: the checkpoint's
        # belief still holds, the world has moved.
        result = dirty_recovery_drill(
            self.gate,
            {"schema": "v3", "tasks": []},
            (WorldWrite("tasks", [{"id": 1}]),),
            freshness_seq=7,
            witness_keys=("schema",),
        )
        self.assertIs(result.status, GateVerdictStatus.FLAGGED)
        self.assertTrue(result.stale_detected)
        self.assertEqual(result.verdict.seq_advance, 1)
        self.assertEqual(len(result.writes), 1)

    def test_a_drill_over_a_changed_schema_rejects_the_recovery(self):
        # The world changed the very thing the checkpoint vouched for.
        result = dirty_recovery_drill(
            self.gate,
            {"schema": "v3", "tasks": []},
            (WorldWrite("schema", "v4"),),
            freshness_seq=7,
            witness_keys=("schema",),
        )
        self.assertIs(result.status, GateVerdictStatus.REJECTED)
        self.assertFalse(result.recovered)
        self.assertTrue(result.stale_detected)
        self.assertNotEqual(
            result.verdict.expected_checksum, result.verdict.actual_checksum
        )

    def test_a_drill_with_several_writes_advances_by_the_number_of_writes(self):
        result = dirty_recovery_drill(
            self.gate,
            {"schema": "v3", "tasks": []},
            (
                WorldWrite("tasks", [{"id": 1}]),
                WorldWrite("tasks", [{"id": 1}, {"id": 2}]),
                WorldWrite("tasks", [{"id": 1}, {"id": 2}, {"id": 3}]),
            ),
            freshness_seq=7,
            witness_keys=("schema",),
        )
        self.assertIs(result.status, GateVerdictStatus.FLAGGED)
        self.assertEqual(result.verdict.seq_advance, 3)
        self.assertEqual(result.live_seq, 10)

    def test_a_drill_over_a_clean_world_passes(self):
        # The control: without later writes, the gate waves it through.  This
        # is what makes the dirty cases above meaningful rather than vacuous.
        result = dirty_recovery_drill(
            self.gate,
            {"schema": "v3", "tasks": []},
            (),
            freshness_seq=7,
            witness_keys=("schema",),
        )
        self.assertIs(result.status, GateVerdictStatus.PASS)
        self.assertFalse(result.stale_detected)
        self.assertTrue(result.recovered)

    def test_the_drill_is_a_helper_not_a_production_path(self):
        # The drill lives in the module so the tests can call it, and it
        # reports rather than decides: a flagged recovery is reported as
        # recoverable, and the caller still owns the decision.
        result = dirty_recovery_drill(
            self.gate,
            {"schema": "v3", "tasks": []},
            (WorldWrite("tasks", [{"id": 1}]),),
            freshness_seq=7,
            witness_keys=("schema",),
        )
        self.assertTrue(result.recovered)
        self.assertIn("verdict", result.as_dict())
        self.assertEqual(result.as_dict()["verdict"]["status"], "flagged")

    def test_drill_accepts_a_plain_mapping_with_an_explicit_sequence(self):
        checkpoint = self.gate.create(
            "ck-1", external_state=_Schema.V3, freshness_seq=7
        )
        result = drill(checkpoint, _Schema.V3, live_seq=9)
        self.assertIs(result.status, GateVerdictStatus.FLAGGED)
        self.assertEqual(result.live_seq, 9)
        self.assertEqual(result.verdict.seq_advance, 2)

    def test_drill_refuses_a_live_state_it_cannot_read(self):
        checkpoint = self.gate.create(
            "ck-1", external_state=_Schema.V3, freshness_seq=7
        )
        with self.assertRaises(StaleCheckpointGateError):
            drill(checkpoint, "not-a-world")


class WitnessShapeTests(unittest.TestCase):
    """The witness is a record, and it says what it saw."""

    def test_the_witness_reports_the_checksum_and_the_sequence(self):
        gate = StaleCheckpointGate()
        checkpoint = gate.create(
            "ck-1", external_state=_Schema.V3, freshness_seq=7, created_seq=9
        )
        witness = checkpoint.witness
        self.assertEqual(witness.external_checksum, checksum_of_state(_Schema.V3))
        self.assertEqual(witness.freshness_seq, 7)
        self.assertEqual(witness.created_seq, 9)
        self.assertEqual(witness.as_dict()["external_checksum"], witness.external_checksum)

    def test_a_checkpoint_without_an_id_is_refused(self):
        gate = StaleCheckpointGate()
        with self.assertRaises(MissingExternalStateError):
            gate.create("", external_state=_Schema.V3, freshness_seq=7)

    def test_the_verdict_serialises_to_a_dict(self):
        gate = StaleCheckpointGate()
        checkpoint = gate.create(
            "ck-1", external_state=_Schema.V3, freshness_seq=7
        )
        payload = gate.verify(
            checkpoint, checksum_of_state(_Schema.V3), 7
        ).as_dict()
        self.assertEqual(payload["status"], "pass")
        self.assertEqual(payload["checkpoint_id"], "ck-1")
        self.assertEqual(payload["expected_seq"], 7)
        self.assertEqual(payload["actual_seq"], 7)
        self.assertIn("version", payload)

    def test_the_checkpoint_serialises_to_a_dict(self):
        gate = StaleCheckpointGate()
        checkpoint = gate.create(
            "ck-1", external_state=_Schema.V3, freshness_seq=7, session_id="s-1"
        )
        payload = checkpoint.as_dict()
        self.assertEqual(payload["checkpoint_id"], "ck-1")
        self.assertEqual(payload["external_checksum"], checksum_of_state(_Schema.V3))
        self.assertEqual(payload["freshness_seq"], 7)


if __name__ == "__main__":
    unittest.main()
