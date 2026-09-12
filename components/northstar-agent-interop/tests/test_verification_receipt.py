"""Tests for signed, challenge-bound verifier receipts."""
from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from challenge_ledger import ChallengeLedger
from evidence_notarization import (
    EvidenceEnvelope,
    HMACSignatureScheme,
    NotarizationError,
    build_envelope,
)
from key_lifecycle import KeyHistory
from verification_receipt import (
    ReceiptError,
    ReceiptVerification,
    VerificationReceipt,
    issue_verification_receipt,
    verify_receipt,
)
from test_evidence_notarization import SECRET, evidence, make_history

RECEIPT_SECRET = b"verifier-receipt-signing-key-32bytes"
OTHER_RECEIPT_SECRET = b"other-verifier-receipt-key-32bytes"


class Clock:
    def __init__(self, now=1000):
        self.now = now

    def __call__(self):
        return self.now


def make_envelope(root):
    route, lineage, bundle, chain, event, proof, handoff, checkpoint = evidence()
    history, anchor = make_history(root)
    envelope = build_envelope(
        route, lineage, bundle, chain, event, proof, handoff,
        index=0, key_id="k1", history=history,
        signer={"kind": "host", "id": "host-1"},
        scheme=HMACSignatureScheme({"k1": SECRET}),
    )
    return envelope, anchor


def make_ledger(root, clock):
    return ChallengeLedger(
        Path(root) / "ledger", clock=clock, ttl=60,
        nonce_source=lambda n: b"\x11" * n,
    )


class IssueTests(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="receipt-")
        self.addCleanup(shutil.rmtree, self.root, True)
        self.clock = Clock()
        self.envelope, self.anchor = make_envelope(self.root)
        self.ledger = make_ledger(self.root, self.clock)
        self.evidence_scheme = HMACSignatureScheme({"k1": SECRET})
        self.receipt_scheme = HMACSignatureScheme({"rk1": RECEIPT_SECRET})

    def issue(self, **kwargs):
        challenge = self.ledger.issue(verifier_id="verifier-a", key_id="k1")
        options = dict(
            envelope=self.envelope,
            ledger=self.ledger,
            challenge_id=challenge.challenge_id,
            verifier_id="verifier-a",
            evidence_anchor=self.anchor,
            evidence_scheme=self.evidence_scheme,
            receipt_key_id="rk1",
            receipt_scheme=self.receipt_scheme,
            expected_root=self.envelope.disclosure["root_digest"],
        )
        options.update(kwargs)
        return issue_verification_receipt(**options), challenge

    def test_issue_returns_a_signed_receipt_for_a_pinned_envelope(self):
        receipt, challenge = self.issue()
        self.assertIsInstance(receipt, VerificationReceipt)
        self.assertEqual(receipt.schema_version, "northstar.verification-receipt.v1")
        self.assertEqual(receipt.challenge_id, challenge.challenge_id)
        self.assertEqual(receipt.verifier_id, "verifier-a")
        self.assertEqual(receipt.claimed_evidence_state, "verified")
        self.assertEqual(receipt.evidence_root, self.envelope.disclosure["root_digest"])
        self.assertTrue(receipt.signature)

    def test_issue_consumes_the_challenge(self):
        receipt, challenge = self.issue()
        self.assertEqual(receipt.challenge_id, challenge.challenge_id)
        with self.assertRaises(ReceiptError):
            issue_verification_receipt(
                envelope=self.envelope, ledger=self.ledger,
                challenge_id=challenge.challenge_id, verifier_id="verifier-a",
                evidence_anchor=self.anchor, evidence_scheme=self.evidence_scheme,
                receipt_key_id="rk1", receipt_scheme=self.receipt_scheme,
                expected_root=self.envelope.disclosure["root_digest"],
            )

    def test_issue_refuses_wrong_verifier_before_receipt_creation(self):
        challenge = self.ledger.issue(verifier_id="verifier-a", key_id="k1")
        with self.assertRaises(ReceiptError):
            issue_verification_receipt(
                envelope=self.envelope, ledger=self.ledger,
                challenge_id=challenge.challenge_id, verifier_id="verifier-b",
                evidence_anchor=self.anchor, evidence_scheme=self.evidence_scheme,
                receipt_key_id="rk1", receipt_scheme=self.receipt_scheme,
                expected_root=self.envelope.disclosure["root_digest"],
            )

    def test_issue_refuses_revoked_evidence_key(self):
        route, lineage, bundle, chain, event, proof, handoff, _ = evidence()
        history_path = Path(self.root) / "revoked-history.jsonl"
        writer = KeyHistory(history_path)
        writer.introduce("k1", SECRET)
        anchor = writer.records[0].record_digest
        history = KeyHistory(history_path, anchor=anchor)
        history.revoke("k1")
        with self.assertRaises(NotarizationError):
            build_envelope(
                route, lineage, bundle, chain, event, proof, handoff,
                index=0, key_id="k1", history=history,
                signer={"kind": "host", "id": "host-1"},
                scheme=self.evidence_scheme,
            )

    def test_issue_refuses_an_unpinned_evidence_root_when_pinning_is_required(self):
        receipt, _ = self.issue(expected_root=None)
        self.assertEqual(receipt.claimed_evidence_state, "verified-unpinned")
        self.assertIn("root_unpinned", receipt.unverified)

    def test_issue_refuses_a_receipt_scheme_that_returns_bad_signature(self):
        class BadScheme:
            mode = "public-key"
            def sign(self, payload, *, key_id):
                return "bad"
            def verify(self, payload, signature, *, key_id):
                return False
        with self.assertRaises(ReceiptError):
            self.issue(receipt_scheme=BadScheme())


class VerifyTests(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="receipt-")
        self.addCleanup(shutil.rmtree, self.root, True)
        self.clock = Clock()
        self.envelope, self.anchor = make_envelope(self.root)
        self.ledger = make_ledger(self.root, self.clock)
        self.evidence_scheme = HMACSignatureScheme({"k1": SECRET})
        self.receipt_scheme = HMACSignatureScheme({"rk1": RECEIPT_SECRET})
        self.receipt, self.challenge = self._issue()

    def _issue(self):
        challenge = self.ledger.issue(verifier_id="verifier-a", key_id="k1")
        receipt = issue_verification_receipt(
            envelope=self.envelope, ledger=self.ledger,
            challenge_id=challenge.challenge_id, verifier_id="verifier-a",
            evidence_anchor=self.anchor, evidence_scheme=self.evidence_scheme,
            receipt_key_id="rk1", receipt_scheme=self.receipt_scheme,
            expected_root=self.envelope.disclosure["root_digest"],
        )
        return receipt, challenge

    def verify(self, **kwargs):
        options = dict(
            receipt=self.receipt,
            envelope=self.envelope,
            expected_challenge_id=self.challenge.challenge_id,
            expected_verifier_id="verifier-a",
            expected_root=self.envelope.disclosure["root_digest"],
            scheme=self.receipt_scheme,
        )
        options.update(kwargs)
        return verify_receipt(**options)

    def test_pinned_receipt_verifies_as_receipt_only(self):
        result = self.verify()
        self.assertIsInstance(result, ReceiptVerification)
        self.assertEqual(result.state, "receipt-verified")
        self.assertEqual(result.claimed_evidence_state, "verified")
        self.assertIn("receipt-only", result.unverified)
        self.assertIn("same-key", result.unverified)

    def test_receipt_round_trips_through_strict_wire_form(self):
        restored = VerificationReceipt.from_dict(
            json.loads(json.dumps(self.receipt.to_dict(), sort_keys=True))
        )
        self.assertEqual(restored, self.receipt)
        with self.assertRaises(ReceiptError):
            VerificationReceipt.from_dict({**self.receipt.to_dict(), "extra": True})

    def test_altered_envelope_is_rejected_by_digest_binding(self):
        altered = EvidenceEnvelope.from_dict({
            **self.envelope.to_dict(),
            "subject": {**self.envelope.subject, "event_id": "changed"},
        })
        with self.assertRaises(ReceiptError):
            self.verify(envelope=altered)

    def test_altered_challenge_or_verifier_is_rejected(self):
        with self.assertRaises(ReceiptError):
            self.verify(expected_challenge_id="22" * 16)
        with self.assertRaises(ReceiptError):
            self.verify(expected_verifier_id="verifier-b")

    def test_altered_root_or_claimed_state_is_rejected(self):
        with self.assertRaises(ReceiptError):
            self.verify(expected_root="sha256:" + "f" * 64)
        forged = VerificationReceipt(
            self.receipt.schema_version, self.receipt.envelope_digest,
            self.receipt.challenge_id, self.receipt.verifier_id,
            self.receipt.evidence_root, "verified-unpinned",
            self.receipt.unverified, self.receipt.receipt_key_id,
            self.receipt.signature,
        )
        with self.assertRaises(ReceiptError):
            verify_receipt(
                receipt=forged, envelope=self.envelope,
                expected_challenge_id=self.challenge.challenge_id,
                expected_verifier_id="verifier-a",
                expected_root=self.envelope.disclosure["root_digest"],
                scheme=self.receipt_scheme,
            )

    def test_altered_signature_or_receipt_key_is_rejected(self):
        forged = VerificationReceipt(
            self.receipt.schema_version, self.receipt.envelope_digest,
            self.receipt.challenge_id, self.receipt.verifier_id,
            self.receipt.evidence_root, self.receipt.claimed_evidence_state,
            self.receipt.unverified, "other-key", self.receipt.signature,
        )
        with self.assertRaises(ReceiptError):
            verify_receipt(
                receipt=forged, envelope=self.envelope,
                expected_challenge_id=self.challenge.challenge_id,
                expected_verifier_id="verifier-a",
                expected_root=self.envelope.disclosure["root_digest"],
                scheme=self.receipt_scheme,
            )
        forged = VerificationReceipt(
            self.receipt.schema_version, self.receipt.envelope_digest,
            self.receipt.challenge_id, self.receipt.verifier_id,
            self.receipt.evidence_root, self.receipt.claimed_evidence_state,
            self.receipt.unverified, self.receipt.receipt_key_id, "bad-signature",
        )
        with self.assertRaises(ReceiptError):
            self.verify(receipt=forged)

    def test_wrong_receipt_secret_is_rejected(self):
        with self.assertRaises(ReceiptError):
            self.verify(scheme=HMACSignatureScheme({"rk1": OTHER_RECEIPT_SECRET}))

    def test_unpinned_root_is_reported_without_becoming_verified(self):
        root = tempfile.mkdtemp(prefix="receipt-unpinned-")
        self.addCleanup(shutil.rmtree, root, True)
        envelope, anchor = make_envelope(root)
        ledger = make_ledger(root, self.clock)
        challenge = ledger.issue(verifier_id="verifier-a", key_id="k1")
        receipt = issue_verification_receipt(
            envelope=envelope, ledger=ledger,
            challenge_id=challenge.challenge_id, verifier_id="verifier-a",
            evidence_anchor=anchor, evidence_scheme=self.evidence_scheme,
            receipt_key_id="rk1", receipt_scheme=self.receipt_scheme,
            expected_root=None,
        )
        result = verify_receipt(
            receipt=receipt, envelope=envelope,
            expected_challenge_id=challenge.challenge_id,
            expected_verifier_id="verifier-a", expected_root=None,
            scheme=self.receipt_scheme,
        )
        self.assertEqual(result.state, "receipt-verified")
        self.assertEqual(result.claimed_evidence_state, "verified-unpinned")
        self.assertIn("root-unpinned", result.unverified)


if __name__ == "__main__":
    unittest.main()
