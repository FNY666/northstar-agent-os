"""Tests for deterministic, conflict-preserving claim state projection."""
from __future__ import annotations

import unittest

from admission_witness import AdmissionWitness, SCHEMA as WITNESS_SCHEMA, policy_digest
from evidence_admission import EvidenceAdmissionPolicy
from evidence_conflict_ledger import (
    ConflictObservation,
    SCHEMA as CONFLICT_SCHEMA,
    ZERO as CONFLICT_ZERO,
)
from evidence_state_projection import (
    ClaimProjection,
    ProjectionError,
    project_claim,
    project_state,
)


D = lambda char: "sha256:" + char * 64


def policy():
    return EvidenceAdmissionPolicy(
        "northstar.evidence-admission-policy.v1",
        "policy-a", True, True, True, True, False, False, (),
    )


def witness(*, claim=D("a"), root=D("b"), package=D("c"),
            state="admissible", claimed="verified", unverified=()):
    current_policy = policy()
    unsigned = AdmissionWitness(
        WITNESS_SCHEMA, current_policy.to_dict(), policy_digest(current_policy),
        package, claim, root, claimed, state, (), tuple(unverified), "",
    )
    return AdmissionWitness(
        unsigned.schema_version, unsigned.policy, unsigned.policy_digest,
        unsigned.package_digest, unsigned.claim_digest, unsigned.evidence_root,
        unsigned.claimed_evidence_state, unsigned.admission_state,
        unsigned.reasons, unsigned.unverified, unsigned.computed_digest,
    )


def conflict(left, right, reasons=("evidence_root_mismatch",)):
    first, second = sorted((left, right), key=lambda item: item.witness_digest)
    seed = ConflictObservation(
        CONFLICT_SCHEMA, 1, "", first.claim_digest,
        first.witness_digest, second.witness_digest,
        first.evidence_root, second.evidence_root,
        first.claimed_evidence_state, second.claimed_evidence_state,
        tuple(sorted(reasons)), CONFLICT_ZERO, "",
    )
    unsigned = ConflictObservation(
        seed.schema_version, seed.sequence, seed.computed_conflict_id,
        seed.claim_digest, seed.witness_a_digest, seed.witness_b_digest,
        seed.evidence_root_a, seed.evidence_root_b,
        seed.claimed_state_a, seed.claimed_state_b, seed.reasons,
        seed.previous_digest, "",
    )
    return ConflictObservation(
        unsigned.schema_version, unsigned.sequence, unsigned.conflict_id,
        unsigned.claim_digest, unsigned.witness_a_digest, unsigned.witness_b_digest,
        unsigned.evidence_root_a, unsigned.evidence_root_b,
        unsigned.claimed_state_a, unsigned.claimed_state_b, unsigned.reasons,
        unsigned.previous_digest, unsigned.computed_digest,
    )


class ClaimProjectionTests(unittest.TestCase):
    def test_fully_pinned_admissible_witness_projects_supported(self):
        item = witness(unverified=("same-key", "index", "leaf_count"))
        projection = project_claim(item.claim_digest, [item])
        self.assertEqual(projection.state, "supported")
        self.assertTrue(projection.actionable)
        self.assertEqual(projection.witness_digests, (item.witness_digest,))
        self.assertEqual(projection.package_digests, (item.package_digest,))
        self.assertIn("same-key", projection.unverified)

    def test_insufficient_witness_projects_insufficient(self):
        item = witness(state="insufficient", unverified=("root_unpinned",))
        projection = project_claim(item.claim_digest, [item])
        self.assertEqual(projection.state, "insufficient")
        self.assertFalse(projection.actionable)
        self.assertIn("admission_insufficient", projection.reasons)

    def test_unpinned_admissible_witness_projects_unverifiable(self):
        item = witness(unverified=("package_digest_unpinned",))
        projection = project_claim(item.claim_digest, [item])
        self.assertEqual(projection.state, "unverifiable")
        self.assertFalse(projection.actionable)
        self.assertIn("unresolved_trust_pins", projection.reasons)

    def test_empty_claim_projects_unknown(self):
        projection = project_claim(D("a"), [])
        self.assertEqual(projection.state, "unknown")
        self.assertFalse(projection.actionable)
        self.assertIn("no_admission_witness", projection.reasons)

    def test_same_claim_conflict_dominates_support_without_winner(self):
        left = witness(root=D("b"), package=D("c"))
        right = witness(root=D("d"), package=D("e"))
        observation = conflict(left, right)
        projection = project_claim(left.claim_digest, [left, right], [observation])
        self.assertEqual(projection.state, "conflicted")
        self.assertFalse(projection.actionable)
        self.assertEqual(projection.conflict_ids, (observation.conflict_id,))
        self.assertEqual(projection.witness_digests, tuple(sorted((left.witness_digest, right.witness_digest))))
        self.assertEqual(projection.package_digests, tuple(sorted((left.package_digest, right.package_digest))))
        self.assertIn("evidence_root_mismatch", projection.reasons)

    def test_different_claim_conflict_does_not_affect_target(self):
        target = witness(claim=D("a"))
        other_left = witness(claim=D("b"), package=D("d"))
        other_right = witness(claim=D("b"), root=D("e"), package=D("f"))
        projection = project_claim(target.claim_digest, [target], [conflict(other_left, other_right)])
        self.assertEqual(projection.state, "supported")
        self.assertEqual(projection.conflict_ids, ())

    def test_wire_form_is_strict_and_deterministic(self):
        item = witness()
        projection = project_claim(item.claim_digest, [item])
        self.assertEqual(ClaimProjection.from_dict(projection.to_dict()), projection)
        with self.assertRaises(ProjectionError):
            ClaimProjection.from_dict({**projection.to_dict(), "extra": True})
        with self.assertRaises(ProjectionError):
            ClaimProjection.from_dict({})

    def test_malformed_witness_or_conflict_is_rejected(self):
        item = witness()
        with self.assertRaises(ProjectionError):
            project_claim(item.claim_digest, [object()])
        with self.assertRaises(ProjectionError):
            project_claim(item.claim_digest, [item], [object()])


class StateProjectionTests(unittest.TestCase):
    def test_multiple_claims_are_projected_deterministically(self):
        first = witness(claim=D("b"), package=D("d"))
        second = witness(claim=D("a"), package=D("e"), state="insufficient")
        projections = project_state([first, second])
        self.assertEqual(list(projections), [D("a"), D("b")])
        self.assertEqual(projections[D("a")].state, "insufficient")
        self.assertEqual(projections[D("b")].state, "supported")

    def test_conflict_only_claim_is_not_omitted(self):
        left = witness(claim=D("a"), package=D("c"))
        right = witness(claim=D("a"), root=D("d"), package=D("e"))
        projections = project_state([], [conflict(left, right)])
        self.assertIn(D("a"), projections)
        self.assertEqual(projections[D("a")].state, "conflicted")
        self.assertFalse(projections[D("a")].actionable)


if __name__ == "__main__":
    unittest.main()


class SupportedRequiresEvidenceTests(unittest.TestCase):
    def _wire(self, **overrides):
        wire = {
            "schema_version": "northstar.evidence-state-projection.v1",
            "claim_digest": "sha256:" + "a" * 64,
            "state": "supported",
            "actionable": True,
            "witness_digests": [],
            "package_digests": [],
            "conflict_ids": [],
            "reasons": [],
            "unverified": [],
        }
        wire.update(overrides)
        return wire

    def test_supported_without_any_evidence_is_refused(self):
        with self.assertRaises(ProjectionError):
            ClaimProjection.from_dict(self._wire())

    def test_supported_with_a_witness_is_accepted(self):
        projection = ClaimProjection.from_dict(
            self._wire(witness_digests=["sha256:" + "c" * 64])
        )
        self.assertEqual(projection.state, "supported")

    def test_supported_with_only_a_package_is_accepted(self):
        projection = ClaimProjection.from_dict(
            self._wire(package_digests=["sha256:" + "d" * 64])
        )
        self.assertEqual(projection.state, "supported")
