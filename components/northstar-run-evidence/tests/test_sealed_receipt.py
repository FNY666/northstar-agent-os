"""Strict signed SealedRunReceipt contract and offline verification tests."""
import base64
import tempfile
import unittest
from pathlib import Path

import sealed_receipt as receipt_module
from evidence_store import EvidenceStore, HmacTestSigner
from sealed_receipt import (
    CompletionEvidence,
    SealedRunReceipt,
    seal_run_receipt,
    verify_run_receipt,
)


class SealedRunReceiptTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmpdir.cleanup)
        self.path = Path(self.tmpdir.name) / "run.evidence.jsonl"
        self.store = EvidenceStore(self.path, "run-001")
        self.signer = HmacTestSigner("test-key-1", b"test-secret-0123456789")
        self.first, self.completion_entry = self._append_chain()
        self.completion = CompletionEvidence(
            status="finished",
            completed_at=1_800_000_030,
            evidence_entry_digest=self.completion_entry.entry_digest,
            verifier_verdict="passed",
            test_exit_code=0,
        )

    def _append_chain(self):
        first = self.store.append(
            source="durable",
            kind="run.started",
            occurred_at=1_800_000_001,
            subject={"event_id": "event-start"},
            source_id="event-start",
        )
        completion = self.store.append(
            source="verifier",
            kind="run.verified",
            occurred_at=1_800_000_020,
            subject={"verdict": "passed", "test_exit_code": 0},
            source_id="verification-1",
        )
        return first, completion

    def _seal(self, **overrides):
        options = {
            "store": self.store,
            "completion": self.completion,
            "required_sources": ("durable", "verifier"),
            "signer": self.signer,
            "capture_policy_revision": "policy-v1",
            "capture_policy_digest": "sha256:" + "a" * 64,
            "sealed_at": 1_800_000_040,
        }
        options.update(overrides)
        return seal_run_receipt(**options)

    def test_sign_and_verify_complete_run_receipt_against_ledger(self):
        receipt = self._seal()
        self.assertIsInstance(receipt, SealedRunReceipt)
        self.assertEqual(receipt.schema_version, "northstar.sealed-run-receipt.v1")
        self.assertEqual(receipt.run_id, "run-001")
        self.assertEqual(receipt.entry_count, 2)
        self.assertEqual(receipt.first_entry_digest, self.first.entry_digest)
        self.assertEqual(receipt.head_digest, self.completion_entry.entry_digest)
        self.assertEqual(receipt.required_sources, ("durable", "verifier"))
        self.assertEqual(receipt.observed_sources, ("durable", "verifier"))
        self.assertEqual(receipt.missing_sources, ())
        self.assertEqual(
            [(root.source, root.entry_count) for root in receipt.source_roots],
            [("durable", 1), ("verifier", 1)],
        )

        report = verify_run_receipt(
            receipt.to_dict(),
            {self.signer.key_id: self.signer.verifier()},
            store=self.store,
            expected_run_id="run-001",
        )
        self.assertTrue(report.ok)
        self.assertEqual(report.integrity, "verified")
        self.assertEqual(report.completeness, "complete")
        self.assertEqual(report.authenticity, "verified")
        self.assertEqual(report.run_verdict, "verified")
        self.assertEqual(SealedRunReceipt.from_dict(receipt.to_dict()), receipt)
        self.assertEqual(receipt.canonical_json(), SealedRunReceipt.from_dict(receipt.to_dict()).canonical_json())

    def test_global_head_must_match_a_per_source_tail(self):
        malformed = self._seal().to_dict()
        malformed["ledger"]["head_digest"] = "sha256:" + "f" * 64
        with self.assertRaisesRegex(ValueError, "must match a per-source tail"):
            SealedRunReceipt.from_dict(malformed)

    def test_direct_receipt_construction_rejects_mutable_source_collections(self):
        values = dict(self._seal().__dict__)
        values["required_sources"] = list(values["required_sources"])
        with self.assertRaisesRegex(ValueError, "must be immutable tuples"):
            SealedRunReceipt(**values)

    def test_oversized_source_roots_are_rejected_before_item_parsing(self):
        malformed = self._seal().to_dict()
        malformed["ledger"]["source_roots"] = [None] * 257
        with self.assertRaisesRegex(ValueError, "too many source labels"):
            SealedRunReceipt.from_dict(malformed)

    def test_signer_identity_fields_must_be_ascii(self):
        malformed = self._seal().to_dict()
        malformed["signer"]["key_id"] = "tést-key"
        with self.assertRaisesRegex(ValueError, "safe non-empty identifier"):
            SealedRunReceipt.from_dict(malformed)
        malformed = self._seal().to_dict()
        malformed["signer"]["algorithm"] = "hmac-sha256-tést"
        with self.assertRaisesRegex(ValueError, "safe non-empty identifier"):
            SealedRunReceipt.from_dict(malformed)

    def test_signature_limit_is_checked_after_base64_decoding(self):
        too_large = base64.b64encode(
            b"x" * (receipt_module._MAX_SIGNATURE_BYTES + 1)
        ).decode("ascii")
        with self.assertRaisesRegex(ValueError, "signature exceeds the receipt size limit"):
            receipt_module._decode_signature(too_large)

    def test_signature_without_ledger_does_not_claim_integrity_or_verified_run(self):
        receipt = self._seal()
        report = verify_run_receipt(
            receipt,
            {self.signer.key_id: self.signer.verifier()},
        )
        self.assertFalse(report.ok)
        self.assertEqual(report.integrity, "unknown")
        self.assertEqual(report.authenticity, "verified")
        self.assertEqual(report.run_verdict, "unknown")

    def test_unknown_key_is_not_authenticated_even_when_chain_matches(self):
        receipt = self._seal()
        report = verify_run_receipt(receipt, {}, store=self.store)
        self.assertFalse(report.ok)
        self.assertEqual(report.integrity, "verified")
        self.assertEqual(report.authenticity, "unknown-key")
        self.assertEqual(report.run_verdict, "unknown")

    def test_incomplete_signed_receipt_never_gets_verified_run_verdict(self):
        body = self._seal().body_dict()
        body["required_sources"] = ["durable", "runtime", "verifier"]
        body["missing_sources"] = ["runtime"]
        signature = self.signer.sign(receipt_module._signature_input(body))
        raw = {
            **body,
            "signature": base64.b64encode(signature).decode("ascii"),
        }
        report = verify_run_receipt(
            raw,
            {self.signer.key_id: self.signer.verifier()},
            store=self.store,
        )
        self.assertEqual(report.integrity, "verified")
        self.assertEqual(report.completeness, "incomplete")
        self.assertEqual(report.authenticity, "verified")
        self.assertEqual(report.run_verdict, "failed")

    def test_tampered_completion_claim_fails_signature(self):
        receipt = self._seal()
        tampered = receipt.to_dict()
        tampered["completion"]["status"] = "failed"
        report = verify_run_receipt(
            tampered,
            {self.signer.key_id: self.signer.verifier()},
            store=self.store,
        )
        self.assertEqual(report.authenticity, "bad-signature")
        self.assertEqual(report.run_verdict, "failed")

    def test_receipt_does_not_verify_after_ledger_snapshot_moves(self):
        receipt = self._seal()
        self.store.append(
            source="runtime",
            kind="session.closed",
            occurred_at=1_800_000_050,
            subject={"session_id": "session-1"},
            source_id="session-close-1",
        )
        report = verify_run_receipt(
            receipt,
            {self.signer.key_id: self.signer.verifier()},
            store=self.store,
        )
        self.assertEqual(report.authenticity, "verified")
        self.assertEqual(report.integrity, "failed")
        self.assertEqual(report.run_verdict, "failed")

    def test_sealing_rejects_missing_required_sources(self):
        with self.assertRaisesRegex(ValueError, "missing sources: runtime"):
            self._seal(required_sources=("durable", "runtime"))

    def test_sealing_requires_completion_evidence_entry_in_snapshot(self):
        missing = CompletionEvidence(
            status="finished",
            completed_at=1_800_000_030,
            evidence_entry_digest="sha256:" + "0" * 64,
            verifier_verdict="passed",
            test_exit_code=0,
        )
        with self.assertRaisesRegex(ValueError, "not present in this ledger"):
            self._seal(completion=missing)

    def test_nonterminal_and_ill_typed_completion_claims_are_rejected(self):
        for status in ("planned", "running", "waiting", None, []):
            with self.subTest(status=status):
                with self.assertRaises(ValueError):
                    CompletionEvidence(
                        status=status,
                        completed_at=1_800_000_030,
                        evidence_entry_digest=self.completion_entry.entry_digest,
                        verifier_verdict="passed",
                        test_exit_code=0,
                    )
        for code in (True, -1, 256, 1.5):
            with self.subTest(test_exit_code=code):
                with self.assertRaises(ValueError):
                    CompletionEvidence(
                        status="finished",
                        completed_at=1_800_000_030,
                        evidence_entry_digest=self.completion_entry.entry_digest,
                        verifier_verdict="passed",
                        test_exit_code=code,
                    )

    def test_signed_failed_or_unverified_outcome_is_not_reported_as_verified(self):
        failed = CompletionEvidence(
            status="failed",
            completed_at=1_800_000_030,
            evidence_entry_digest=self.completion_entry.entry_digest,
            verifier_verdict="failed",
            test_exit_code=1,
        )
        receipt = self._seal(completion=failed)
        report = verify_run_receipt(
            receipt,
            {self.signer.key_id: self.signer.verifier()},
            store=self.store,
        )
        self.assertEqual(report.integrity, "verified")
        self.assertEqual(report.authenticity, "verified")
        self.assertEqual(report.run_verdict, "failed")

        unknown_verifier = CompletionEvidence(
            status="finished",
            completed_at=1_800_000_030,
            evidence_entry_digest=self.completion_entry.entry_digest,
            verifier_verdict="not-run",
            test_exit_code=None,
        )
        receipt = self._seal(completion=unknown_verifier)
        report = verify_run_receipt(
            receipt,
            {self.signer.key_id: self.signer.verifier()},
            store=self.store,
        )
        self.assertEqual(report.run_verdict, "unknown")

    def test_wrong_key_identity_or_algorithm_is_rejected(self):
        receipt = self._seal()

        class PermissiveWrongIdentity:
            key_id = "different-key"
            algorithm = "hmac-sha256-test"

            def verify(self, data, signature):
                return True

        class PermissiveWrongAlgorithm:
            key_id = "test-key-1"
            algorithm = "different-algorithm"

            def verify(self, data, signature):
                return True

        for verifier in (PermissiveWrongIdentity(), PermissiveWrongAlgorithm()):
            with self.subTest(verifier=verifier.__class__.__name__):
                report = verify_run_receipt(
                    receipt,
                    {"test-key-1": verifier},
                    store=self.store,
                )
                self.assertEqual(report.authenticity, "bad-signature")
                self.assertEqual(report.run_verdict, "failed")

    def test_non_boolean_verifier_result_and_invalid_resolver_are_not_trusted(self):
        receipt = self._seal()

        class TruthyNonBooleanVerifier:
            key_id = "test-key-1"
            algorithm = "hmac-sha256-test"

            def verify(self, data, signature):
                return "yes"

        report = verify_run_receipt(
            receipt,
            {"test-key-1": TruthyNonBooleanVerifier()},
            store=self.store,
        )
        self.assertEqual(report.authenticity, "bad-signature")
        self.assertEqual(report.run_verdict, "failed")

        class NonAsciiIdentityVerifier:
            key_id = "tést-key"
            algorithm = "hmac-sha256-test"

            def verify(self, data, signature):
                return True

        report = verify_run_receipt(
            receipt,
            {"test-key-1": NonAsciiIdentityVerifier()},
            store=self.store,
        )
        self.assertEqual(report.authenticity, "bad-signature")

        class NonStringIdentityVerifier:
            key_id = object()
            algorithm = "hmac-sha256-test"

            def verify(self, data, signature):
                return True

        report = verify_run_receipt(
            receipt,
            {"test-key-1": NonStringIdentityVerifier()},
            store=self.store,
        )
        self.assertEqual(report.authenticity, "bad-signature")

        class RaisingVerifier:
            key_id = "test-key-1"
            algorithm = "hmac-sha256-test"

            def verify(self, data, signature):
                raise RuntimeError("do-not-leak-this")

        report = verify_run_receipt(
            receipt,
            {"test-key-1": RaisingVerifier()},
            store=self.store,
        )
        self.assertEqual(report.authenticity, "bad-signature")
        self.assertIn("RuntimeError", report.errors[0])
        self.assertNotIn("do-not-leak-this", " ".join(report.errors))

        report = verify_run_receipt(receipt, None, store=self.store)
        self.assertEqual(report.authenticity, "unknown-key")
        self.assertEqual(report.run_verdict, "unknown")

        class ExplodingResolver(dict):
            def get(self, key, default=None):
                raise RuntimeError("resolver unavailable")

        report = verify_run_receipt(receipt, ExplodingResolver(), store=self.store)
        self.assertEqual(report.authenticity, "unknown-key")
        self.assertEqual(report.run_verdict, "unknown")

    def test_malformed_shape_signature_and_expected_identity_fail_closed(self):
        receipt = self._seal()
        class ReceiptSubclass(SealedRunReceipt):
            pass

        subclassed = ReceiptSubclass(**receipt.__dict__)
        report = verify_run_receipt(
            subclassed,
            {self.signer.key_id: self.signer.verifier()},
            store=self.store,
        )
        self.assertEqual(report.authenticity, "malformed")

        malformed = receipt.to_dict()
        malformed["unexpected"] = True
        report = verify_run_receipt(malformed, {}, store=self.store)
        self.assertEqual(report.authenticity, "malformed")
        self.assertEqual(report.run_verdict, "failed")

        bad_signature = receipt.to_dict()
        bad_signature["signature"] = base64.b64encode(b"not-the-signature").decode("ascii")
        report = verify_run_receipt(
            bad_signature,
            {self.signer.key_id: self.signer.verifier()},
            store=self.store,
        )
        self.assertEqual(report.authenticity, "bad-signature")

        report = verify_run_receipt(
            receipt,
            {self.signer.key_id: self.signer.verifier()},
            store=self.store,
            expected_run_id="different-run",
        )
        self.assertEqual(report.integrity, "failed")
        self.assertEqual(report.run_verdict, "failed")

    def test_unknown_source_snapshot_and_noncanonical_signer_fields_rejected(self):
        receipt = self._seal()
        malformed = receipt.to_dict()
        malformed["ledger"]["source_roots"][0]["unknown"] = "field"
        with self.assertRaisesRegex(ValueError, "unknown fields"):
            SealedRunReceipt.from_dict(malformed)

        with self.assertRaises(ValueError):
            self._seal(required_sources=("z-source", "durable", "verifier"))


if __name__ == "__main__":
    unittest.main()
