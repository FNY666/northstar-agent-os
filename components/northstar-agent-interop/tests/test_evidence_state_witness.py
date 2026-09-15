"""Tests for replayable evidence-state witnesses."""
from __future__ import annotations

import json
import unittest

from evidence_state_witness import (
    EvidenceStateWitness,
    StateWitnessError,
    StateWitnessVerdict,
    make_state_witness,
    verify_state_witness,
)
from test_evidence_state_projection import D, conflict, witness


class StateWitnessTests(unittest.TestCase):
    def test_supported_witness_is_deterministic_and_replayable(self):
        item = witness(unverified=("same-key", "index", "leaf_count"))
        first = make_state_witness(item.claim_digest, [item])
        second = make_state_witness(item.claim_digest, [item])
        self.assertEqual(first, second)
        self.assertEqual(first.claimed_state, "supported")
        self.assertEqual(first.projection["state"], "supported")
        self.assertEqual(first.witness_digests, (item.witness_digest,))
        verdict = verify_state_witness(first, expected_state_digest=first.state_digest)
        self.assertIsInstance(verdict, StateWitnessVerdict)
        self.assertEqual(verdict.state, "state-witness-verified")
        self.assertEqual(verdict.claimed_state, "supported")
        self.assertEqual(verdict.unverified, ("index", "leaf_count", "same-key"))

    def test_conflict_witness_preserves_both_sources_without_winner(self):
        left = witness(root=D("b"), package=D("c"))
        right = witness(root=D("d"), package=D("e"))
        observation = conflict(left, right)
        state = make_state_witness(left.claim_digest, [right, left], [observation])
        self.assertEqual(state.claimed_state, "conflicted")
        self.assertEqual(state.conflict_ids, (observation.conflict_id,))
        self.assertEqual(state.witness_digests, tuple(sorted((left.witness_digest, right.witness_digest))))
        self.assertEqual(state.projection["actionable"], False)
        self.assertIn("evidence_root_mismatch", state.projection["reasons"])

    def test_unknown_without_source_is_not_witnessable(self):
        with self.assertRaises(StateWitnessError):
            make_state_witness(D("a"), [])

    def test_source_claim_mismatch_and_malformed_source_fail_closed(self):
        item = witness(claim=D("a"))
        with self.assertRaises(StateWitnessError):
            make_state_witness(D("b"), [item])
        with self.assertRaises(StateWitnessError):
            make_state_witness(D("a"), [object()])
        with self.assertRaises(StateWitnessError):
            make_state_witness(D("a"), [item], [object()])

    def test_wire_form_is_strict_and_contains_no_raw_payload(self):
        item = witness()
        state = make_state_witness(item.claim_digest, [item])
        self.assertEqual(EvidenceStateWitness.from_dict(state.to_dict()), state)
        with self.assertRaises(StateWitnessError):
            EvidenceStateWitness.from_dict({**state.to_dict(), "extra": True})
        with self.assertRaises(StateWitnessError):
            EvidenceStateWitness.from_dict({})
        encoded = json.dumps(state.to_dict(), sort_keys=True)
        self.assertNotIn("prompt", encoded)
        self.assertNotIn("event_id", encoded)
        self.assertNotIn("secret", encoded)

    def test_missing_external_state_digest_is_explicit(self):
        item = witness()
        state = make_state_witness(item.claim_digest, [item])
        verdict = verify_state_witness(state)
        self.assertEqual(verdict.state, "state-witness-verified-unpinned")
        self.assertIn("state_digest_unpinned", verdict.unverified)

    def test_tampered_state_source_or_projection_is_rejected(self):
        item = witness()
        state = make_state_witness(item.claim_digest, [item])
        forged = EvidenceStateWitness(
            state.schema_version, state.claim_digest, state.admission_witnesses,
            state.conflicts, {**state.projection, "state": "blocked"},
            state.claimed_state, state.witness_digests, state.conflict_ids,
            state.state_digest,
        )
        with self.assertRaises(StateWitnessError):
            verify_state_witness(forged, expected_state_digest=state.state_digest)
        forged = EvidenceStateWitness(
            state.schema_version, state.claim_digest, state.admission_witnesses,
            state.conflicts, state.projection, state.claimed_state,
            state.witness_digests, state.conflict_ids, "sha256:" + "f" * 64,
        )
        with self.assertRaises(StateWitnessError):
            verify_state_witness(forged, expected_state_digest=state.state_digest)
        with self.assertRaises(StateWitnessError):
            verify_state_witness(state, expected_state_digest="sha256:" + "e" * 64)

    def test_conflict_for_other_claim_is_not_admissible_source(self):
        item = witness(claim=D("a"))
        left = witness(claim=D("b"), package=D("c"))
        right = witness(claim=D("b"), root=D("d"), package=D("e"))
        with self.assertRaises(StateWitnessError):
            make_state_witness(item.claim_digest, [item], [conflict(left, right)])


if __name__ == "__main__":
    unittest.main()
