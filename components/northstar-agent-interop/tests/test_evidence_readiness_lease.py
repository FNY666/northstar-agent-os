"""Tests for freshness leases over fully pinned evidence readiness."""
from __future__ import annotations

import unittest

from evidence_readiness_lease import (
    EvidenceReadinessLease,
    LeaseError,
    LeaseVerdict,
    issue_readiness_lease,
    verify_readiness_lease,
)
from evidence_state_projection import ClaimProjection, SCHEMA as PROJECTION_SCHEMA
from plan_evidence_decision import (
    EvidencePlanManifest,
    EvidencePlanStep,
    make_plan_evidence_decision,
)

D = lambda char: "sha256:" + char * 64


def projection(claim, *, state="supported", unverified=()):
    if state == "unknown":
        return ClaimProjection(PROJECTION_SCHEMA, claim, state, False, (), (), (), ("unknown",), tuple(sorted(unverified)))
    return ClaimProjection(
        PROJECTION_SCHEMA, claim, state, state == "supported",
        (D("c"),), (D("d"),), (D("e"),) if state == "conflicted" else (),
        (), tuple(sorted(unverified)),
    )


def manifest(claim):
    return EvidencePlanManifest(
        "northstar.evidence-plan-manifest.v1",
        (EvidencePlanStep("step-a", claim, "required evidence"),),
    )


class LeaseFixture(unittest.TestCase):
    def setUp(self):
        self.claim = D("a")
        self.manifest = manifest(self.claim)
        self.projections = {self.claim: projection(self.claim, unverified=("same-key", "index"))}
        self.decision = make_plan_evidence_decision(self.manifest, self.projections)
        self.pins = dict(
            expected_decision_digest=self.decision.decision_digest,
            expected_manifest_digest=self.manifest.manifest_digest,
            expected_gate_digest=self.decision.gate["gate_digest"],
        )

    def issue(self, **updates):
        options = dict(
            decision=self.decision,
            manifest=self.manifest,
            projections=self.projections,
            now=1000,
            ttl=60,
            **self.pins,
        )
        options.update(updates)
        return issue_readiness_lease(**options)

    def verify(self, lease, **updates):
        options = dict(
            lease=lease,
            decision=self.decision,
            manifest=self.manifest,
            projections=self.projections,
            now=1010,
            expected_lease_digest=lease.lease_digest,
            **self.pins,
        )
        options.update(updates)
        return verify_readiness_lease(**options)


class LeaseIssueTests(LeaseFixture):
    def test_fully_pinned_ready_decision_issues_lease(self):
        lease = self.issue()
        self.assertEqual(lease.schema_version, "northstar.evidence-readiness-lease.v1")
        self.assertEqual(lease.plan_id, "plan-evidence:" + self.manifest.manifest_digest[7:23])
        self.assertEqual(lease.decision_digest, self.decision.decision_digest)
        self.assertEqual(lease.manifest_digest, self.manifest.manifest_digest)
        self.assertEqual(lease.gate_digest, self.decision.gate["gate_digest"])
        self.assertEqual((lease.issued_at, lease.expires_at), (1000, 1060))
        self.assertFalse(lease.execution_authorized)
        self.assertTrue(lease.lease_digest.startswith("sha256:"))

    def test_wire_form_round_trips_strictly(self):
        lease = self.issue()
        self.assertEqual(EvidenceReadinessLease.from_dict(lease.to_dict()), lease)
        with self.assertRaises(LeaseError):
            EvidenceReadinessLease.from_dict({**lease.to_dict(), "extra": True})
        with self.assertRaises(LeaseError):
            EvidenceReadinessLease.from_dict({})

    def test_only_ready_fully_pinned_decisions_issue(self):
        with self.assertRaises(LeaseError):
            self.issue(expected_gate_digest=None)
        blocked = make_plan_evidence_decision(
            self.manifest, {self.claim: projection(self.claim, state="conflicted")}
        )
        with self.assertRaises(LeaseError):
            issue_readiness_lease(
                decision=blocked, manifest=self.manifest,
                projections={self.claim: projection(self.claim, state="conflicted")},
                now=1000, ttl=60,
                expected_decision_digest=blocked.decision_digest,
                expected_manifest_digest=self.manifest.manifest_digest,
                expected_gate_digest=blocked.gate["gate_digest"],
            )
        unknown = make_plan_evidence_decision(
            self.manifest, {self.claim: projection(self.claim, state="unknown")}
        )
        with self.assertRaises(LeaseError):
            issue_readiness_lease(
                decision=unknown, manifest=self.manifest,
                projections={self.claim: projection(self.claim, state="unknown")},
                now=1000, ttl=60,
                expected_decision_digest=unknown.decision_digest,
                expected_manifest_digest=self.manifest.manifest_digest,
                expected_gate_digest=unknown.gate["gate_digest"],
            )

    def test_invalid_time_ttl_and_raw_action_fields_fail_closed(self):
        for now, ttl in ((True, 60), (1000, 0), (1000, -1)):
            with self.assertRaises(LeaseError):
                self.issue(now=now, ttl=ttl)
        lease = self.issue()
        rendered = str(lease.to_dict())
        for forbidden in ("prompt", "command", "action", "event_id", "secret"):
            self.assertNotIn(forbidden, rendered)


class LeaseVerificationTests(LeaseFixture):
    def setUp(self):
        super().setUp()
        self.lease = self.issue()

    def test_pinned_active_lease_is_valid_but_not_authorized(self):
        verdict = self.verify(self.lease)
        self.assertIsInstance(verdict, LeaseVerdict)
        self.assertEqual(verdict.state, "lease-valid")
        self.assertEqual(verdict.claimed_decision_state, "ready")
        self.assertFalse(verdict.execution_authorized)
        self.assertEqual(verdict.unverified, ("index", "same-key"))

    def test_missing_external_lease_pin_is_explicit(self):
        verdict = self.verify(self.lease, expected_lease_digest=None)
        self.assertEqual(verdict.state, "lease-valid-unpinned")
        self.assertIn("lease_digest_unpinned", verdict.unverified)

    def test_expired_lease_is_not_valid(self):
        verdict = self.verify(self.lease, now=1061)
        self.assertEqual(verdict.state, "lease-expired")
        self.assertFalse(verdict.execution_authorized)
        self.assertIn("lease_expired", verdict.reasons)

    def test_decision_manifest_gate_projection_or_digest_drift_is_rejected(self):
        with self.assertRaises(LeaseError):
            self.verify(self.lease, expected_decision_digest=D("f"))
        with self.assertRaises(LeaseError):
            self.verify(self.lease, expected_manifest_digest=D("e"))
        with self.assertRaises(LeaseError):
            self.verify(self.lease, expected_gate_digest=D("d"))
        with self.assertRaises(LeaseError):
            self.verify(self.lease, projections={self.claim: projection(self.claim, state="insufficient")})
        forged = EvidenceReadinessLease(
            self.lease.schema_version, self.lease.plan_id,
            self.lease.decision_digest, self.lease.manifest_digest,
            self.lease.gate_digest, self.lease.issued_at,
            self.lease.expires_at, False, D("c"),
        )
        with self.assertRaises(LeaseError):
            self.verify(forged)

    def test_decision_binding_is_exact(self):
        changed_manifest = manifest(D("b"))
        changed_decision = make_plan_evidence_decision(changed_manifest, {D("b"): projection(D("b"))})
        with self.assertRaises(LeaseError):
            verify_readiness_lease(
                self.lease, changed_decision, changed_manifest,
                {D("b"): projection(D("b"))}, now=1010,
                expected_lease_digest=self.lease.lease_digest,
                expected_decision_digest=changed_decision.decision_digest,
                expected_manifest_digest=changed_manifest.manifest_digest,
                expected_gate_digest=changed_decision.gate["gate_digest"],
            )


if __name__ == "__main__":
    unittest.main()
