"""Tests for a deterministic, offline portable evidence package."""
from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from checkpoint_chain_witness import make_witness
from evidence_bundle import build_bundle
from evidence_notarization import EvidenceEnvelope, HMACSignatureScheme, build_envelope
from evidence_package import (
    EvidencePackage,
    PackageError,
    PackageVerdict,
    build_package,
    verify_package,
)
from key_history_snapshot import make_snapshot
from test_evidence_notarization import SECRET, evidence, make_history
from test_verification_receipt import RECEIPT_SECRET, make_ledger
from verification_receipt import issue_verification_receipt


class Clock:
    def __init__(self, now=1000):
        self.now = now

    def __call__(self):
        return self.now


class PackageFixture(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="package-")
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
        self.evidence_scheme = HMACSignatureScheme({"k1": SECRET})
        self.receipt_scheme = HMACSignatureScheme({"rk1": RECEIPT_SECRET})

    def package(self, with_receipt=False):
        receipt = None
        if with_receipt:
            clock = Clock()
            ledger = make_ledger(self.root, clock)
            challenge = ledger.issue(verifier_id="verifier-a", key_id="k1")
            receipt = issue_verification_receipt(
                envelope=self.envelope, ledger=ledger,
                challenge_id=challenge.challenge_id, verifier_id="verifier-a",
                evidence_anchor=self.key_anchor, evidence_scheme=self.evidence_scheme,
                receipt_key_id="rk1", receipt_scheme=self.receipt_scheme,
                expected_root=self.envelope.disclosure["root_digest"],
            )
        return build_package(
            self.envelope, self.witness, self.snapshot, verifier_receipt=receipt
        )


class PackageCreationTests(PackageFixture):
    def test_package_is_deterministic_and_round_trips(self):
        package = self.package()
        again = self.package()
        self.assertEqual(package, again)
        self.assertEqual(EvidencePackage.from_dict(package.to_dict()), package)
        self.assertEqual(package.package_digest, again.package_digest)
        self.assertTrue(package.package_digest.startswith("sha256:"))

    def test_wire_schema_is_strict(self):
        package = self.package()
        with self.assertRaises(PackageError):
            EvidencePackage.from_dict({**package.to_dict(), "extra": True})
        with self.assertRaises(PackageError):
            EvidencePackage.from_dict({})

    def test_package_adds_no_raw_lineage_or_key_material(self):
        package = self.package()
        encoded = json.dumps(package.to_dict(), sort_keys=True)
        self.assertEqual(package.envelope["subject"], self.envelope.subject)
        self.assertNotIn("\"lineage\"", encoded)
        self.assertNotIn("\"prompt\"", encoded)
        self.assertNotIn(SECRET.decode(), encoded)
        self.assertNotIn(SECRET.hex(), encoded)

    def test_optional_receipt_is_preserved(self):
        package = self.package(with_receipt=True)
        self.assertIsNotNone(package.verifier_receipt)
        self.assertEqual(package.verifier_receipt["schema_version"], "northstar.verification-receipt.v1")

    def test_mismatched_witness_is_rejected_at_build(self):
        route, lineage, bundle, chain, event, proof, handoff, _ = evidence()
        other_chain = type(chain)()
        other_chain.append(build_bundle([{"event_id": "other-evidence", "sequence": 99}]))
        other_witness = make_witness(other_chain)
        with self.assertRaises(PackageError):
            build_package(self.envelope, other_witness, self.snapshot)


class PackageVerificationTests(PackageFixture):
    def test_pinned_package_is_verified(self):
        package = self.package()
        verdict = verify_package(
            package,
            key_anchor=self.key_anchor,
            evidence_scheme=self.evidence_scheme,
            expected_root=self.envelope.disclosure["root_digest"],
            expected_package_digest=package.package_digest,
            expected_checkpoint_chain_digest=package.checkpoint_witness["chain_digest"],
        )
        self.assertIsInstance(verdict, PackageVerdict)
        self.assertEqual(verdict.state, "verified")
        self.assertEqual(verdict.package_digest, package.package_digest)

    def test_missing_external_pins_are_explicit(self):
        package = self.package()
        verdict = verify_package(
            package, key_anchor=self.key_anchor, evidence_scheme=self.evidence_scheme,
        )
        self.assertEqual(verdict.state, "verified-unpinned")
        self.assertIn("package_digest_unpinned", verdict.unverified)
        self.assertIn("checkpoint_chain_digest_unpinned", verdict.unverified)

    def test_wrong_package_or_chain_pin_is_rejected(self):
        package = self.package()
        with self.assertRaises(PackageError):
            verify_package(
                package, key_anchor=self.key_anchor, evidence_scheme=self.evidence_scheme,
                expected_package_digest="sha256:" + "f" * 64,
            )
        with self.assertRaises(PackageError):
            verify_package(
                package, key_anchor=self.key_anchor, evidence_scheme=self.evidence_scheme,
                expected_checkpoint_chain_digest="sha256:" + "e" * 64,
            )

    def test_tampering_any_component_is_rejected(self):
        package = self.package()
        for field, value in (
            ("package_digest", "sha256:" + "f" * 64),
            ("envelope", {**package.envelope, "signature": "tampered"}),
            ("checkpoint_witness", {**package.checkpoint_witness, "head_root": "sha256:" + "f" * 64}),
            ("key_snapshot", {**package.key_snapshot, "head_digest": "sha256:" + "f" * 64}),
        ):
            forged = dict(package.to_dict())
            forged[field] = value
            with self.assertRaises(PackageError):
                verify_package(
                    EvidencePackage.from_dict(forged),
                    key_anchor=self.key_anchor, evidence_scheme=self.evidence_scheme,
                    expected_root=self.envelope.disclosure["root_digest"],
                )

    def test_optional_receipt_requires_verifier_context(self):
        package = self.package(with_receipt=True)
        with self.assertRaises(PackageError):
            verify_package(
                package, key_anchor=self.key_anchor, evidence_scheme=self.evidence_scheme,
                expected_root=self.envelope.disclosure["root_digest"],
                expected_package_digest=package.package_digest,
                expected_checkpoint_chain_digest=package.checkpoint_witness["chain_digest"],
            )

    def test_receipt_is_verified_as_receipt_only(self):
        package = self.package(with_receipt=True)
        receipt = package.verifier_receipt
        assert receipt is not None
        verdict = verify_package(
            package, key_anchor=self.key_anchor, evidence_scheme=self.evidence_scheme,
            expected_root=self.envelope.disclosure["root_digest"],
            expected_package_digest=package.package_digest,
            expected_checkpoint_chain_digest=package.checkpoint_witness["chain_digest"],
            receipt_scheme=self.receipt_scheme,
            expected_challenge_id=receipt["challenge_id"],
            expected_verifier_id=receipt["verifier_id"],
        )
        self.assertEqual(verdict.state, "verified")
        self.assertIn("receipt-only", verdict.unverified)


if __name__ == "__main__":
    unittest.main()
