"""Tests for policy-bound, replayable admission witnesses."""
from __future__ import annotations

import json
import shutil
import tempfile
import unittest

from admission_witness import (
    AdmissionWitness,
    AdmissionWitnessVerdict,
    WitnessError,
    make_admission_witness,
    policy_digest,
    verify_admission_witness,
)
from checkpoint_chain_witness import make_witness
from evidence_admission import EvidenceAdmissionPolicy
from evidence_notarization import HMACSignatureScheme, build_envelope
from evidence_package import EvidencePackage, build_package
from key_history_snapshot import make_snapshot
from test_evidence_notarization import SECRET, evidence, make_history


class WitnessFixture(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="admission-witness-")
        self.addCleanup(shutil.rmtree, self.root, True)
        route, lineage, bundle, chain, event, proof, handoff, _ = evidence()
        self.history, self.key_anchor = make_history(self.root)
        self.envelope = build_envelope(
            route, lineage, bundle, chain, event, proof, handoff,
            index=0, key_id="k1", history=self.history,
            signer={"kind": "host", "id": "host-1"},
            scheme=HMACSignatureScheme({"k1": SECRET}),
        )
        self.package = build_package(
            self.envelope, make_witness(chain), make_snapshot(self.history)
        )
        self.scheme = HMACSignatureScheme({"k1": SECRET})

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

    def witness(self, policy=None, package=None, **updates):
        package = self.package if package is None else package
        policy = self.policy() if policy is None else policy
        options = dict(
            package=package,
            policy=policy,
            key_anchor=self.key_anchor,
            evidence_scheme=self.scheme,
            expected_root=self.envelope.disclosure["root_digest"],
            expected_package_digest=package.package_digest,
            expected_checkpoint_chain_digest=package.checkpoint_witness["chain_digest"],
        )
        options.update(updates)
        return make_admission_witness(**options)


class WitnessCreationTests(WitnessFixture):
    def test_admissible_policy_result_has_deterministic_witness(self):
        first = self.witness()
        second = self.witness()
        self.assertEqual(first, second)
        self.assertEqual(first.admission_state, "admissible")
        self.assertEqual(first.package_digest, self.package.package_digest)
        self.assertEqual(first.policy_digest, policy_digest(self.policy()))
        self.assertTrue(first.witness_digest.startswith("sha256:"))

    def test_insufficient_policy_result_can_be_witnessed(self):
        policy = self.policy(require_external_root=False,
                             require_external_package_digest=False,
                             require_external_checkpoint_chain_digest=False,
                             require_key_anchor=False,
                             allow_unpinned=False)
        witness = self.witness(
            policy=policy, key_anchor=None, expected_root=None,
            expected_package_digest=None, expected_checkpoint_chain_digest=None,
        )
        self.assertEqual(witness.admission_state, "insufficient")
        self.assertIn("unresolved_external_pins", witness.reasons)

    def test_wire_schema_is_strict_and_round_trips(self):
        witness = self.witness()
        self.assertEqual(AdmissionWitness.from_dict(witness.to_dict()), witness)
        with self.assertRaises(WitnessError):
            AdmissionWitness.from_dict({**witness.to_dict(), "extra": True})
        with self.assertRaises(WitnessError):
            AdmissionWitness.from_dict({})

    def test_policy_digest_changes_when_same_id_policy_changes(self):
        first = self.policy()
        second = self.policy(forbidden_unverified=("same-key",))
        self.assertEqual(first.policy_id, second.policy_id)
        self.assertNotEqual(policy_digest(first), policy_digest(second))

    def test_witness_has_no_secret_or_raw_prompt(self):
        witness = self.witness()
        encoded = json.dumps(witness.to_dict(), sort_keys=True)
        self.assertNotIn(SECRET.decode(), encoded)
        self.assertNotIn(SECRET.hex(), encoded)
        self.assertNotIn("\"prompt\"", encoded)

    def test_unverifiable_package_is_not_witnessable(self):
        forged = EvidencePackage(
            self.package.schema_version,
            {**self.package.envelope, "signature": "bad"},
            self.package.checkpoint_witness,
            self.package.key_snapshot,
            self.package.verifier_receipt,
            self.package.package_digest,
        )
        with self.assertRaises(WitnessError):
            self.witness(package=forged)


class WitnessReplayTests(WitnessFixture):
    def verify(self, witness=None, package=None, **updates):
        witness = self.witness() if witness is None else witness
        package = self.package if package is None else package
        options = dict(
            witness=witness,
            package=package,
            expected_witness_digest=witness.witness_digest,
            expected_policy_digest=witness.policy_digest,
            key_anchor=self.key_anchor,
            evidence_scheme=self.scheme,
            expected_root=self.envelope.disclosure["root_digest"],
            expected_package_digest=package.package_digest,
            expected_checkpoint_chain_digest=package.checkpoint_witness["chain_digest"],
        )
        options.update(updates)
        return verify_admission_witness(**options)

    def test_fully_pinned_witness_replays_exactly(self):
        witness = self.witness()
        verdict = self.verify(witness)
        self.assertIsInstance(verdict, AdmissionWitnessVerdict)
        self.assertEqual(verdict.state, "witness-verified")
        self.assertEqual(verdict.claimed_admission_state, "admissible")
        self.assertEqual(verdict.unverified, ("index", "leaf_count", "same-key"))

    def test_missing_witness_or_policy_pins_are_explicit(self):
        witness = self.witness()
        verdict = self.verify(witness, expected_witness_digest=None,
                              expected_policy_digest=None)
        self.assertEqual(verdict.state, "witness-verified-unpinned")
        self.assertIn("witness_digest_unpinned", verdict.unverified)
        self.assertIn("policy_digest_unpinned", verdict.unverified)

    def test_tampered_policy_package_or_witness_is_rejected(self):
        witness = self.witness()
        altered_policy = {**witness.policy, "allow_unpinned": True}
        forged = AdmissionWitness(
            witness.schema_version, altered_policy, witness.policy_digest,
            witness.package_digest, witness.claim_digest, witness.evidence_root,
            witness.claimed_evidence_state, witness.admission_state,
            witness.reasons, witness.unverified, witness.witness_digest,
        )
        with self.assertRaises(WitnessError):
            self.verify(forged)
        forged = AdmissionWitness(
            witness.schema_version, witness.policy, witness.policy_digest,
            "sha256:" + "f" * 64, witness.claim_digest, witness.evidence_root,
            witness.claimed_evidence_state, witness.admission_state,
            witness.reasons, witness.unverified, witness.witness_digest,
        )
        with self.assertRaises(WitnessError):
            self.verify(forged)
        forged = AdmissionWitness(
            witness.schema_version, witness.policy, witness.policy_digest,
            witness.package_digest, witness.claim_digest, witness.evidence_root,
            witness.claimed_evidence_state, witness.admission_state,
            witness.reasons, witness.unverified, "sha256:" + "e" * 64,
        )
        with self.assertRaises(WitnessError):
            self.verify(forged)

    def test_policy_replay_detects_same_id_semantic_drift(self):
        witness = self.witness()
        with self.assertRaises(WitnessError):
            self.verify(witness, expected_policy_digest=policy_digest(
                self.policy(forbidden_unverified=("same-key",))
            ))

    def test_replayed_result_fields_cannot_be_changed(self):
        witness = self.witness()
        forged = AdmissionWitness(
            witness.schema_version, witness.policy, witness.policy_digest,
            witness.package_digest, witness.claim_digest, witness.evidence_root,
            "verified-unpinned", witness.admission_state,
            witness.reasons, witness.unverified, witness.witness_digest,
        )
        with self.assertRaises(WitnessError):
            self.verify(forged)

    def test_insufficient_witness_replays_as_insufficient(self):
        policy = self.policy(require_external_root=False,
                             require_external_package_digest=False,
                             require_external_checkpoint_chain_digest=False,
                             require_key_anchor=False,
                             allow_unpinned=False)
        witness = self.witness(
            policy=policy, key_anchor=None, expected_root=None,
            expected_package_digest=None, expected_checkpoint_chain_digest=None,
        )
        verdict = self.verify(
            witness,
            key_anchor=None, expected_root=None,
            expected_package_digest=None, expected_checkpoint_chain_digest=None,
        )
        self.assertEqual(verdict.state, "witness-verified-unpinned")
        self.assertEqual(verdict.claimed_admission_state, "insufficient")


if __name__ == "__main__":
    unittest.main()
