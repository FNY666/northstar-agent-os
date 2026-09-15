"""Tests for replayable plan evidence decisions without execution authority."""
from __future__ import annotations

import unittest

from evidence_state_projection import ClaimProjection, SCHEMA as PROJECTION_SCHEMA
from plan_evidence_decision import (
    EvidencePlanManifest,
    EvidencePlanStep,
    PlanDecisionError,
    PlanDecisionVerdict,
    PlanEvidenceDecision,
    make_plan_evidence_decision,
    verify_plan_evidence_decision,
)

D = lambda char: "sha256:" + char * 64


def projection(claim, *, state="supported", reason=(), unverified=()):
    return ClaimProjection(
        PROJECTION_SCHEMA,
        claim,
        state,
        state == "supported",
        (D("c"),) if state != "unknown" else (),
        (D("d"),) if state != "unknown" else (),
        (D("e"),) if state == "conflicted" else (),
        tuple(sorted(reason)),
        tuple(sorted(unverified)),
    )


def manifest(*steps):
    return EvidencePlanManifest("northstar.evidence-plan-manifest.v1", tuple(steps))


class ManifestTests(unittest.TestCase):
    def test_manifest_is_canonical_and_deterministic(self):
        first = manifest(
            EvidencePlanStep("step-b", D("b"), "second evidence"),
            EvidencePlanStep("step-a", D("a"), "first evidence"),
        )
        normalized = EvidencePlanManifest.from_dict(first.to_dict())
        self.assertEqual([step.step_id for step in normalized.steps], ["step-a", "step-b"])
        self.assertTrue(normalized.manifest_digest.startswith("sha256:"))
        self.assertEqual(EvidencePlanManifest.from_dict(normalized.to_dict()), normalized)

    def test_manifest_rejects_duplicate_step_or_claim(self):
        duplicate_step = {
            "schema_version": "northstar.evidence-plan-manifest.v1",
            "steps": [
                {"step_id": "same", "claim_digest": D("a"), "rationale": "one"},
                {"step_id": "same", "claim_digest": D("b"), "rationale": "two"},
            ],
            "manifest_digest": D("f"),
        }
        with self.assertRaises(PlanDecisionError):
            EvidencePlanManifest.from_dict(duplicate_step)
        duplicate_claim = {
            "schema_version": "northstar.evidence-plan-manifest.v1",
            "steps": [
                {"step_id": "one", "claim_digest": D("a"), "rationale": "one"},
                {"step_id": "two", "claim_digest": D("a"), "rationale": "two"},
            ],
            "manifest_digest": D("f"),
        }
        with self.assertRaises(PlanDecisionError):
            EvidencePlanManifest.from_dict(duplicate_claim)

    def test_manifest_rejects_action_prompt_and_unknown_fields(self):
        valid = manifest(EvidencePlanStep("step-a", D("a"), "evidence only")).to_dict()
        for field in ("action", "command", "prompt", "raw_output", "secret"):
            forged = dict(valid)
            forged[field] = "not permitted"
            with self.assertRaises(PlanDecisionError):
                EvidencePlanManifest.from_dict(forged)
        with self.assertRaises(PlanDecisionError):
            EvidencePlanManifest.from_dict({})


class DecisionTests(unittest.TestCase):
    def setUp(self):
        self.a, self.b = D("a"), D("b")
        self.manifest = manifest(
            EvidencePlanStep("step-a", self.a, "claim a"),
            EvidencePlanStep("step-b", self.b, "claim b"),
        )

    def make(self, projections):
        return make_plan_evidence_decision(self.manifest, projections)

    def test_all_supported_is_ready_but_never_authorized(self):
        decision = self.make({self.a: projection(self.a), self.b: projection(self.b)})
        self.assertEqual(decision.state, "ready")
        self.assertFalse(decision.execution_authorized)
        self.assertEqual(decision.gate["state"], "ready")
        self.assertTrue(decision.decision_digest.startswith("sha256:"))

    def test_blocked_and_unknown_flow_through_from_gate(self):
        blocked = self.make({self.a: projection(self.a, state="conflicted", reason=("root_mismatch",)), self.b: projection(self.b)})
        self.assertEqual(blocked.state, "blocked")
        self.assertFalse(blocked.execution_authorized)
        self.assertIn(self.a, blocked.blocked_claims)
        unknown = self.make({self.a: projection(self.a), self.b: projection(self.b, state="unknown", reason=("missing",))})
        self.assertEqual(unknown.state, "unknown")
        self.assertIn(self.b, unknown.unknown_claims)

    def test_wire_form_is_strict_and_no_raw_prompt_is_added(self):
        decision = self.make({self.a: projection(self.a), self.b: projection(self.b)})
        self.assertEqual(PlanEvidenceDecision.from_dict(decision.to_dict()), decision)
        with self.assertRaises(PlanDecisionError):
            PlanEvidenceDecision.from_dict({**decision.to_dict(), "extra": True})
        rendered = str(decision.to_dict())
        self.assertNotIn("prompt", rendered)
        self.assertNotIn("event_id", rendered)
        self.assertNotIn("secret", rendered)


class DecisionReplayTests(unittest.TestCase):
    def setUp(self):
        self.claim = D("a")
        self.manifest = manifest(EvidencePlanStep("step-a", self.claim, "claim a"))
        self.projections = {self.claim: projection(self.claim, unverified=("same-key", "index"))}
        self.decision = make_plan_evidence_decision(self.manifest, self.projections)

    def verify(self, decision=None, **updates):
        decision = self.decision if decision is None else decision
        options = dict(
            decision=decision,
            manifest=self.manifest,
            projections=self.projections,
            expected_decision_digest=decision.decision_digest,
            expected_manifest_digest=self.manifest.manifest_digest,
            expected_gate_digest=decision.gate["gate_digest"],
        )
        options.update(updates)
        return verify_plan_evidence_decision(**options)

    def test_pinned_decision_replays_with_authorization_false(self):
        verdict = self.verify()
        self.assertIsInstance(verdict, PlanDecisionVerdict)
        self.assertEqual(verdict.state, "decision-verified")
        self.assertEqual(verdict.claimed_state, "ready")
        self.assertFalse(verdict.execution_authorized)
        self.assertEqual(verdict.unverified, ("index", "same-key"))

    def test_missing_external_pins_are_explicit(self):
        verdict = self.verify(expected_decision_digest=None,
                              expected_manifest_digest=None,
                              expected_gate_digest=None)
        self.assertEqual(verdict.state, "decision-verified-unpinned")
        self.assertIn("decision_digest_unpinned", verdict.unverified)
        self.assertIn("manifest_digest_unpinned", verdict.unverified)
        self.assertIn("gate_digest_unpinned", verdict.unverified)

    def test_tampered_manifest_gate_state_or_digest_is_rejected(self):
        forged = PlanEvidenceDecision(
            self.decision.schema_version, self.decision.manifest,
            self.decision.manifest_digest, self.decision.gate,
            "blocked", self.decision.blocked_claims,
            self.decision.unknown_claims, self.decision.execution_authorized,
            self.decision.decision_digest,
        )
        with self.assertRaises(PlanDecisionError):
            self.verify(forged)
        forged = PlanEvidenceDecision(
            self.decision.schema_version,
            {**self.decision.manifest, "steps": [{"step_id": "step-a", "claim_digest": D("b"), "rationale": "changed"}]},
            self.decision.manifest_digest, self.decision.gate,
            self.decision.state, self.decision.blocked_claims,
            self.decision.unknown_claims, self.decision.execution_authorized,
            self.decision.decision_digest,
        )
        with self.assertRaises(PlanDecisionError):
            self.verify(forged)
        with self.assertRaises(PlanDecisionError):
            self.verify(expected_gate_digest=D("f"))

    def test_replayed_projection_change_is_rejected(self):
        with self.assertRaises(PlanDecisionError):
            verify_plan_evidence_decision(
                self.decision,
                manifest=self.manifest,
                projections={self.claim: projection(self.claim, state="insufficient")},
                expected_decision_digest=self.decision.decision_digest,
                expected_manifest_digest=self.manifest.manifest_digest,
                expected_gate_digest=self.decision.gate["gate_digest"],
            )


if __name__ == "__main__":
    unittest.main()
