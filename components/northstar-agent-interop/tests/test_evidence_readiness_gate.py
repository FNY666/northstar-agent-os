"""Tests for conservative evidence readiness gates."""
from __future__ import annotations

import unittest

from evidence_readiness_gate import (
    EvidenceReadinessGate,
    GateError,
    GateVerification,
    EvidenceRequirement,
    evaluate_readiness,
    verify_readiness_gate,
)
from evidence_state_projection import ClaimProjection, SCHEMA as PROJECTION_SCHEMA

D = lambda char: "sha256:" + char * 64


def projection(claim, *, state="supported", package="c", witness="d", reasons=(), unverified=()):
    if state == "unknown":
        return ClaimProjection(
            PROJECTION_SCHEMA, claim, state, False, (), (), (),
            tuple(reasons), tuple(unverified),
        )
    return ClaimProjection(
        PROJECTION_SCHEMA,
        claim,
        state,
        state == "supported",
        (D(witness),),
        (D(package),),
        (D("e"),) if state == "conflicted" else (),
        tuple(reasons),
        tuple(unverified),
    )


class ReadinessGateTests(unittest.TestCase):
    def requirements(self, *claims):
        return [EvidenceRequirement(claim, "required evidence") for claim in claims]

    def test_all_supported_requirements_are_ready_but_never_authorized(self):
        first, second = D("a"), D("b")
        gate = evaluate_readiness(
            "plan-1", self.requirements(first, second),
            {first: projection(first), second: projection(second, package="f", witness="e")},
        )
        self.assertEqual(gate.state, "ready")
        self.assertFalse(gate.execution_authorized)
        self.assertEqual(gate.blocked_claims, ())
        self.assertEqual(gate.unknown_claims, ())
        self.assertTrue(gate.gate_digest.startswith("sha256:"))

    def test_missing_or_unknown_requirement_is_unknown(self):
        first, second = D("a"), D("b")
        missing = evaluate_readiness("plan-1", self.requirements(first, second), {first: projection(first)})
        self.assertEqual(missing.state, "unknown")
        self.assertEqual(missing.unknown_claims, (second,))
        self.assertIn("missing_claim_projection", missing.reasons)

        unknown = evaluate_readiness("plan-1", self.requirements(first), {first: projection(first, state="unknown", reasons=("no_admission_witness",))})
        self.assertEqual(unknown.state, "unknown")
        self.assertEqual(unknown.unknown_claims, (first,))

    def test_conflicted_insufficient_and_unverifiable_are_blocked(self):
        claim = D("a")
        for state in ("conflicted", "insufficient", "unverifiable"):
            gate = evaluate_readiness("plan-1", self.requirements(claim), {claim: projection(claim, state=state, reasons=(state + "_reason",))})
            self.assertEqual(gate.state, "blocked")
            self.assertEqual(gate.blocked_claims, (claim,))
            self.assertFalse(gate.execution_authorized)
            self.assertIn("blocked_claim:" + state, gate.reasons)

    def test_blocked_dominates_unknown(self):
        blocked, unknown = D("a"), D("b")
        gate = evaluate_readiness(
            "plan-1", self.requirements(blocked, unknown),
            {blocked: projection(blocked, state="conflicted", reasons=("root_mismatch",)),
             unknown: projection(unknown, state="unknown", reasons=("missing",))},
        )
        self.assertEqual(gate.state, "blocked")
        self.assertEqual(gate.blocked_claims, (blocked,))
        self.assertEqual(gate.unknown_claims, (unknown,))

    def test_duplicate_requirement_and_bad_plan_id_fail_closed(self):
        claim = D("a")
        with self.assertRaises(GateError):
            evaluate_readiness("plan-1", self.requirements(claim, claim), {claim: projection(claim)})
        with self.assertRaises(GateError):
            evaluate_readiness("bad/plan", self.requirements(claim), {claim: projection(claim)})
        with self.assertRaises(GateError):
            evaluate_readiness("plan-1", [], {})

    def test_projection_mapping_key_must_match_claim_digest(self):
        claim = D("a")
        with self.assertRaises(GateError):
            evaluate_readiness("plan-1", self.requirements(claim), {claim: projection(D("b"))})
        with self.assertRaises(GateError):
            evaluate_readiness("plan-1", self.requirements(claim), {claim: object()})

    def test_wire_form_is_deterministic_and_strict(self):
        claim = D("a")
        gate = evaluate_readiness("plan-1", self.requirements(claim), {claim: projection(claim)})
        self.assertEqual(EvidenceReadinessGate.from_dict(gate.to_dict()), gate)
        with self.assertRaises(GateError):
            EvidenceReadinessGate.from_dict({**gate.to_dict(), "extra": True})
        with self.assertRaises(GateError):
            EvidenceReadinessGate.from_dict({})

    def test_gate_and_provenance_do_not_contain_raw_prompt_or_event(self):
        claim = D("a")
        gate = evaluate_readiness("plan-1", self.requirements(claim), {claim: projection(claim)})
        text = str(gate.to_dict())
        self.assertNotIn("prompt", text)
        self.assertNotIn("event_id", text)
        self.assertEqual(gate.projections[0]["claim_digest"], claim)


class ReadinessReplayTests(unittest.TestCase):
    def requirement(self, claim):
        return [EvidenceRequirement(claim, "required evidence")]

    def build(self):
        claim = D("a")
        req = self.requirement(claim)
        projections = {claim: projection(claim)}
        return claim, req, projections, evaluate_readiness("plan-1", req, projections)

    def test_fully_pinned_gate_replays_exactly(self):
        claim, req, projections, gate = self.build()
        verdict = verify_readiness_gate(
            gate, plan_id="plan-1", requirements=req, projections=projections,
            expected_gate_digest=gate.gate_digest,
        )
        self.assertIsInstance(verdict, GateVerification)
        self.assertEqual(verdict.state, "gate-verified")
        self.assertEqual(verdict.claimed_state, "ready")
        self.assertFalse(verdict.execution_authorized)

    def test_missing_gate_pin_is_explicit(self):
        claim, req, projections, gate = self.build()
        verdict = verify_readiness_gate(gate, plan_id="plan-1", requirements=req, projections=projections)
        self.assertEqual(verdict.state, "gate-verified-unpinned")
        self.assertIn("gate_digest_unpinned", verdict.unverified)

    def test_tampered_gate_or_replayed_projection_is_rejected(self):
        claim, req, projections, gate = self.build()
        forged = EvidenceReadinessGate(
            gate.schema_version, gate.plan_id, gate.requirements, gate.projections,
            "blocked", gate.blocked_claims, gate.unknown_claims, gate.reasons,
            gate.execution_authorized, gate.gate_digest,
        )
        with self.assertRaises(GateError):
            verify_readiness_gate(forged, plan_id="plan-1", requirements=req, projections=projections,
                                  expected_gate_digest=gate.gate_digest)
        with self.assertRaises(GateError):
            verify_readiness_gate(gate, plan_id="plan-1", requirements=req,
                                  projections={claim: projection(claim, state="insufficient")},
                                  expected_gate_digest=gate.gate_digest)

    def test_plan_or_requirement_substitution_is_rejected(self):
        claim, req, projections, gate = self.build()
        with self.assertRaises(GateError):
            verify_readiness_gate(gate, plan_id="plan-other", requirements=req, projections=projections)
        with self.assertRaises(GateError):
            verify_readiness_gate(gate, plan_id="plan-1", requirements=[EvidenceRequirement(D("b"), "other")], projections=projections)


if __name__ == "__main__":
    unittest.main()
