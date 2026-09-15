"""Tests for final evidence-readiness preflight composition."""
from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

from evidence_readiness_lease import issue_readiness_lease
from evidence_readiness_lease_registry import EvidenceReadinessLeaseRegistry
from evidence_readiness_preflight import (
    EvidenceReadinessPreflight,
    PreflightError,
    evaluate_preflight,
)
from plan_evidence_decision import EvidencePlanManifest, EvidencePlanStep, make_plan_evidence_decision
from readiness_lease_witness import make_registry_witness
from evidence_state_projection import ClaimProjection, SCHEMA as PROJECTION_SCHEMA

D = lambda char: "sha256:" + char * 64


class Clock:
    def __init__(self, now=1000): self.now = now
    def __call__(self): return self.now


def projection(claim, state="supported"):
    return ClaimProjection(
        PROJECTION_SCHEMA, claim, state, state == "supported",
        (D("c"),) if state != "unknown" else (),
        (D("d"),) if state != "unknown" else (),
        (), (), (),
    )


class PreflightFixture(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="preflight-")
        self.addCleanup(shutil.rmtree, self.root, True)
        self.clock = Clock()
        self.claim = D("a")
        self.manifest = EvidencePlanManifest(
            "northstar.evidence-plan-manifest.v1",
            (EvidencePlanStep("step-a", self.claim, "required evidence"),),
        )
        self.projections = {self.claim: projection(self.claim)}
        self.decision = make_plan_evidence_decision(self.manifest, self.projections)
        pins = dict(
            expected_decision_digest=self.decision.decision_digest,
            expected_manifest_digest=self.manifest.manifest_digest,
            expected_gate_digest=self.decision.gate["gate_digest"],
        )
        self.lease = issue_readiness_lease(
            self.decision, self.manifest, self.projections,
            now=1000, ttl=60, **pins,
        )
        self.registry = EvidenceReadinessLeaseRegistry(Path(self.root) / "registry")
        self.registry.register(self.lease)
        self.registry_witness = make_registry_witness(
            self.registry, self.lease.lease_digest, now=1000,
        )
        self.kw = dict(
            lease=self.lease,
            registry_witness=self.registry_witness,
            registry=self.registry,
            decision=self.decision,
            manifest=self.manifest,
            projections=self.projections,
            now=1010,
            expected_lease_digest=self.lease.lease_digest,
            expected_registry_witness_digest=self.registry_witness.witness_digest,
            expected_decision_digest=self.decision.decision_digest,
            expected_manifest_digest=self.manifest.manifest_digest,
            expected_gate_digest=self.decision.gate["gate_digest"],
        )


class PreflightTests(PreflightFixture):
    def test_current_all_pins_is_ready_but_not_authorized(self):
        result = evaluate_preflight(**self.kw)
        self.assertIsInstance(result, EvidenceReadinessPreflight)
        self.assertEqual(result.state, "preflight-ready")
        self.assertFalse(result.execution_authorized)
        self.assertEqual(result.unverified, ())
        self.assertTrue(result.preflight_digest.startswith("sha256:"))

    def test_missing_external_pin_is_unpinned(self):
        kw = dict(self.kw)
        kw["expected_registry_witness_digest"] = None
        result = evaluate_preflight(**kw)
        self.assertEqual(result.state, "preflight-unpinned")
        self.assertIn("registry_witness_digest_unpinned", result.unverified)
        self.assertFalse(result.execution_authorized)

    def test_expired_lease_is_not_ready(self):
        kw = dict(self.kw, now=1061)
        result = evaluate_preflight(**kw)
        self.assertEqual(result.state, "preflight-expired")
        self.assertFalse(result.execution_authorized)

    def test_registry_revocation_dominates_lease_validity(self):
        self.registry.revoke(self.lease.lease_digest)
        result = evaluate_preflight(**self.kw)
        self.assertEqual(result.state, "preflight-revoked")
        self.assertFalse(result.execution_authorized)

    def test_registry_append_makes_witness_stale(self):
        other = issue_readiness_lease(
            self.decision, self.manifest, self.projections,
            now=1000, ttl=120,
            expected_decision_digest=self.decision.decision_digest,
            expected_manifest_digest=self.manifest.manifest_digest,
            expected_gate_digest=self.decision.gate["gate_digest"],
        )
        self.registry.register(other)
        result = evaluate_preflight(**self.kw)
        self.assertEqual(result.state, "preflight-stale")
        self.assertFalse(result.execution_authorized)

    def test_decision_drift_is_rejected(self):
        changed_projection = {self.claim: projection(self.claim, state="conflicted")}
        kw = dict(self.kw, projections=changed_projection)
        with self.assertRaises(PreflightError):
            evaluate_preflight(**kw)

    def test_malformed_source_is_rejected(self):
        with self.assertRaises(PreflightError):
            evaluate_preflight(**dict(self.kw, lease=object()))


if __name__ == "__main__": unittest.main()
