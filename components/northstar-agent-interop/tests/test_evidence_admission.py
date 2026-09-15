"""Tests for policy-driven evidence admission and conflict preservation."""
from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from checkpoint_chain_witness import make_witness
from evidence_admission import (
    AdmissionResult,
    ConflictComparison,
    EvidenceAdmissionPolicy,
    PolicyError,
    admit_package,
    compare_admissions,
)
from evidence_notarization import HMACSignatureScheme, build_envelope
from evidence_package import EvidencePackage, build_package
from key_history_snapshot import make_snapshot
from test_evidence_notarization import SECRET, evidence, make_history
from test_verification_receipt import RECEIPT_SECRET, Clock, make_ledger
from verification_receipt import issue_verification_receipt


class AdmissionFixture(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="admission-")
        self.addCleanup(shutil.rmtree, self.root, True)
        route, lineage, bundle, chain, event, proof, handoff, _ = evidence()
        self.history, self.key_anchor = make_history(self.root)
        self.envelope = build_envelope(
            route, lineage, bundle, chain, event, proof, handoff,
            index=0, key_id="k1", history=self.history,
            signer={"kind": "host", "id": "host-1"},
            scheme=HMACSignatureScheme({"k1": SECRET}),
        )
        self.witness = make_witness(chain)
        self.snapshot = make_snapshot(self.history)
        self.package = build_package(self.envelope, self.witness, self.snapshot)
        self.evidence_scheme = HMACSignatureScheme({"k1": SECRET})

    def policy(self, **updates):
        values = dict(
            policy_id="policy-a",
            require_external_root=True,
            require_external_package_digest=True,
            require_external_checkpoint_chain_digest=True,
            require_key_anchor=True,
            require_receipt=False,
            allow_unpinned=False,
            forbidden_unverified=(),
        )
        values.update(updates)
        return EvidenceAdmissionPolicy("northstar.evidence-admission-policy.v1", **values)

    def admit(self, policy=None, package=None, **updates):
        package = self.package if package is None else package
        policy = self.policy() if policy is None else policy
        options = dict(
            package=package,
            policy=policy,
            key_anchor=self.key_anchor,
            evidence_scheme=self.evidence_scheme,
            expected_root=self.envelope.disclosure["root_digest"],
            expected_package_digest=package.package_digest,
            expected_checkpoint_chain_digest=package.checkpoint_witness["chain_digest"],
        )
        options.update(updates)
        return admit_package(**options)


class PolicyTests(AdmissionFixture):
    def test_policy_wire_form_is_strict_and_deterministic(self):
        policy = self.policy(forbidden_unverified=("same-key", "receipt-only"))
        self.assertEqual(EvidenceAdmissionPolicy.from_dict(policy.to_dict()), policy)
        with self.assertRaises(PolicyError):
            EvidenceAdmissionPolicy.from_dict({**policy.to_dict(), "extra": True})
        with self.assertRaises(PolicyError):
            EvidenceAdmissionPolicy.from_dict({})

    def test_fully_pinned_permissive_policy_is_admissible(self):
        result = self.admit()
        self.assertIsInstance(result, AdmissionResult)
        self.assertEqual(result.state, "admissible")
        self.assertEqual(result.policy_id, "policy-a")
        self.assertEqual(result.evidence_root, self.envelope.disclosure["root_digest"])
        self.assertTrue(result.claim_digest.startswith("sha256:"))
        self.assertIn("same-key", result.unverified)

    def test_missing_required_external_pins_are_insufficient(self):
        result = self.admit(expected_root=None, expected_package_digest=None,
                            expected_checkpoint_chain_digest=None)
        self.assertEqual(result.state, "insufficient")
        self.assertIn("external_root_required", result.reasons)
        self.assertIn("external_package_digest_required", result.reasons)
        self.assertIn("external_checkpoint_chain_digest_required", result.reasons)

    def test_missing_key_anchor_is_insufficient(self):
        result = self.admit(key_anchor=None)
        self.assertEqual(result.state, "insufficient")
        self.assertIn("key_anchor_required", result.reasons)

    def test_forbidden_same_key_boundary_is_insufficient(self):
        policy = self.policy(forbidden_unverified=("same-key",))
        result = self.admit(policy=policy)
        self.assertEqual(result.state, "insufficient")
        self.assertIn("forbidden_unverified:same-key", result.reasons)

    def test_allow_unpinned_is_explicit_policy_decision(self):
        policy = self.policy(
            require_external_root=False,
            require_external_package_digest=False,
            require_external_checkpoint_chain_digest=False,
            require_key_anchor=False,
            allow_unpinned=True,
        )
        result = self.admit(
            policy=policy, key_anchor=None, expected_root=None,
            expected_package_digest=None, expected_checkpoint_chain_digest=None,
        )
        self.assertEqual(result.state, "admissible")
        self.assertIn("root_unpinned", result.unverified)
        self.assertIn("package_digest_unpinned", result.unverified)

    def test_unpinned_package_without_explicit_permission_is_insufficient(self):
        policy = self.policy(
            require_external_root=False,
            require_external_package_digest=False,
            require_external_checkpoint_chain_digest=False,
            require_key_anchor=False,
            allow_unpinned=False,
        )
        result = self.admit(
            policy=policy, key_anchor=None, expected_root=None,
            expected_package_digest=None, expected_checkpoint_chain_digest=None,
        )
        self.assertEqual(result.state, "insufficient")
        self.assertIn("unresolved_external_pins", result.reasons)

    def test_invalid_package_is_unverifiable(self):
        forged = EvidencePackage(
            self.package.schema_version,
            {**self.package.envelope, "signature": "bad"},
            self.package.checkpoint_witness,
            self.package.key_snapshot,
            self.package.verifier_receipt,
            self.package.package_digest,
        )
        result = self.admit(package=forged)
        self.assertEqual(result.state, "unverifiable")
        self.assertIn("package_verification_failed", result.reasons)

    def test_receipt_requirement_is_enforced(self):
        policy = self.policy(require_receipt=True)
        result = self.admit(policy=policy)
        self.assertEqual(result.state, "insufficient")
        self.assertIn("verifier_receipt_required", result.reasons)

    def test_valid_receipt_satisfies_receipt_requirement(self):
        ledger = make_ledger(self.root, Clock())
        challenge = ledger.issue(verifier_id="verifier-a", key_id="k1")
        receipt_scheme = HMACSignatureScheme({"rk1": RECEIPT_SECRET})
        receipt = issue_verification_receipt(
            envelope=self.envelope, ledger=ledger,
            challenge_id=challenge.challenge_id, verifier_id="verifier-a",
            evidence_anchor=self.key_anchor, evidence_scheme=self.evidence_scheme,
            receipt_key_id="rk1", receipt_scheme=receipt_scheme,
            expected_root=self.envelope.disclosure["root_digest"],
        )
        package = build_package(self.envelope, self.witness, self.snapshot,
                                verifier_receipt=receipt)
        policy = self.policy(require_receipt=True)
        result = self.admit(
            policy=policy, package=package,
            receipt_scheme=receipt_scheme,
            expected_challenge_id=challenge.challenge_id,
            expected_verifier_id="verifier-a",
        )
        self.assertEqual(result.state, "admissible")
        self.assertIn("receipt-only", result.unverified)


class ConflictTests(AdmissionFixture):
    def result(self, *, claim=None, root=None, evidence_state="verified", package_digest=None):
        return AdmissionResult(
            "admissible", "policy-a",
            self.admit().claim_digest if claim is None else claim,
            self.envelope.disclosure["root_digest"] if root is None else root,
            evidence_state,
            self.package.package_digest if package_digest is None else package_digest,
            (), (),
        )

    def test_equal_claim_root_and_state_are_consistent(self):
        comparison = compare_admissions(self.result(), self.result())
        self.assertIsInstance(comparison, ConflictComparison)
        self.assertEqual(comparison.state, "consistent")
        self.assertEqual(comparison.reasons, ())

    def test_same_claim_different_root_is_preserved_as_conflict(self):
        left = self.result()
        right = self.result(root="sha256:" + "f" * 64,
                            package_digest="sha256:" + "e" * 64)
        comparison = compare_admissions(left, right)
        self.assertEqual(comparison.state, "conflicting")
        self.assertIn("evidence_root_mismatch", comparison.reasons)
        self.assertEqual(comparison.left_package_digest, left.package_digest)
        self.assertEqual(comparison.right_package_digest, right.package_digest)

    def test_same_claim_different_claimed_state_is_conflict(self):
        comparison = compare_admissions(self.result(), self.result(evidence_state="verified-unpinned"))
        self.assertEqual(comparison.state, "conflicting")
        self.assertIn("claimed_evidence_state_mismatch", comparison.reasons)

    def test_different_claims_are_incomparable(self):
        comparison = compare_admissions(self.result(), self.result(claim="sha256:" + "a" * 64))
        self.assertEqual(comparison.state, "incomparable")
        self.assertIn("claim_digest_mismatch", comparison.reasons)

    def test_malformed_admission_is_rejected(self):
        with self.assertRaises(PolicyError):
            compare_admissions(object(), self.result())


if __name__ == "__main__":
    unittest.main()
