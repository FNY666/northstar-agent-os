"""Tests for attested_receipts (ninety-second batch)."""

import hashlib
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from attested_receipts import (
    ATTESTATION_SCHEMA_VERSION,
    EVIDENCE_KIND_LADDER,
    AttestationVerdict,
    AttestedReceiptError,
    QuoteVerifier,
    SoftwareAttestor,
    attach_attestation,
    attestation_audit_event,
    call_binding_digest,
    kind_rank,
    receipt_binding_digest,
    strength_at_least,
    verify_attestation,
)


def _secret(label: str) -> bytes:
    return hashlib.sha256(f"northstar-test-attested-receipts:{label}".encode()).digest()


def _receipt(args_hex: str | None = None, result_hex: str | None = None, issued_at: int = 1_789_000_000) -> dict:
    args_hex = args_hex or "a" * 64
    result_hex = result_hex or "b" * 64
    return {
        "schema_version": "northstar.tool-receipt.v1",
        "receipt_id": f"tool:{args_hex}:{result_hex}",
        "tool_name": "workspace.write_file",
        "arguments_digest": args_hex,
        "result_digest": result_hex,
        "issued_at": issued_at,
    }


class TaxonomyTests(unittest.TestCase):
    def test_ladder_order(self):
        self.assertEqual(EVIDENCE_KIND_LADDER, ("zkml", "opml", "tee", "software"))

    def test_rank_ordering(self):
        self.assertLess(kind_rank("zkml"), kind_rank("opml"))
        self.assertLess(kind_rank("opml"), kind_rank("tee"))
        self.assertLess(kind_rank("tee"), kind_rank("software"))

    def test_unknown_kind_raises(self):
        with self.assertRaises(AttestedReceiptError):
            kind_rank("sgx-pinky-promise")

    def test_strength_at_least(self):
        self.assertTrue(strength_at_least("tee", "software"))
        self.assertTrue(strength_at_least("tee", "tee"))
        self.assertTrue(strength_at_least("zkml", "tee"))
        self.assertFalse(strength_at_least("software", "tee"))
        self.assertFalse(strength_at_least("opml", "zkml"))


class BindingTests(unittest.TestCase):
    def test_binding_is_deterministic(self):
        self.assertEqual(call_binding_digest("a" * 64, "b" * 64), call_binding_digest("a" * 64, "b" * 64))

    def test_binding_differs_per_call(self):
        self.assertNotEqual(
            call_binding_digest("a" * 64, "b" * 64), call_binding_digest("a" * 64, "c" * 64)
        )

    def test_binding_rejects_malformed(self):
        with self.assertRaises(AttestedReceiptError):
            call_binding_digest("nope", "b" * 64)
        with self.assertRaises(AttestedReceiptError):
            call_binding_digest("a" * 64, "B" * 64)  # uppercase not canonical

    def test_receipt_binding_digest(self):
        receipt = _receipt()
        self.assertEqual(receipt_binding_digest(receipt), call_binding_digest("a" * 64, "b" * 64))
        with self.assertRaises(AttestedReceiptError):
            receipt_binding_digest({"nope": True})


class SoftwareAttestorTests(unittest.TestCase):
    def test_mint_shape(self):
        attestor = SoftwareAttestor(_secret("mint"))
        binding = call_binding_digest("a" * 64, "b" * 64)
        att = attestor.mint(measured_config=binding, issued_at=1_789_000_000)
        self.assertEqual(att["schema_version"], ATTESTATION_SCHEMA_VERSION)
        self.assertEqual(att["evidence_kind"], "software")
        self.assertTrue(att["emulated"])
        self.assertEqual(att["measured_config"], binding)
        # quote_hash matches the quote bytes
        self.assertEqual(
            att["quote_hash"], hashlib.sha256(bytes.fromhex(att["quote_hex"])).hexdigest()
        )

    def test_mint_rejects_short_secret(self):
        with self.assertRaises(AttestedReceiptError):
            SoftwareAttestor(b"too-short")

    def test_verifier_round_trip(self):
        attestor = SoftwareAttestor(_secret("roundtrip"))
        binding = call_binding_digest("a" * 64, "b" * 64)
        att = attestor.mint(measured_config=binding, issued_at=1_789_000_000)
        verifier = attestor.as_verifier()
        measured = verifier.verify(bytes.fromhex(att["quote_hex"]), expected_binding=binding)
        self.assertEqual(measured, binding)

    def test_verifier_rejects_forgery(self):
        attestor = SoftwareAttestor(_secret("forge"))
        binding = call_binding_digest("a" * 64, "b" * 64)
        att = attestor.mint(measured_config=binding, issued_at=1_789_000_000)
        quote = json.loads(bytes.fromhex(att["quote_hex"]).decode())
        quote["measured_config"] = "d" * 64
        forged = json.dumps(quote, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
        with self.assertRaises(AttestedReceiptError):
            attestor.as_verifier().verify(forged, expected_binding=binding)

    def test_wrong_secret_rejects(self):
        attestor = SoftwareAttestor(_secret("one"))
        other = SoftwareAttestor(_secret("two"))
        binding = call_binding_digest("a" * 64, "b" * 64)
        att = attestor.mint(measured_config=binding, issued_at=1_789_000_000)
        with self.assertRaises(AttestedReceiptError):
            other.as_verifier().verify(bytes.fromhex(att["quote_hex"]), expected_binding=binding)


class VerifyAttestationTests(unittest.TestCase):
    def _setup(self, label="v"):
        attestor = SoftwareAttestor(_secret(label))
        receipt = _receipt(issued_at=1_789_000_000)
        binding = receipt_binding_digest(receipt)
        att = attestor.mint(measured_config=binding, issued_at=1_789_000_000)
        verifiers = {"software": attestor.as_verifier()}
        return attestor, receipt, att, verifiers

    def test_valid_software_attestation(self):
        _, receipt, att, verifiers = self._setup()
        verdict = verify_attestation(receipt, att, verifiers=verifiers, now=1_789_000_100)
        self.assertTrue(verdict.allowed)
        self.assertEqual(verdict.evidence_kind, "software")
        self.assertIn("verified", verdict.reason)

    def test_replay_across_calls_denied(self):
        _, receipt_a, att, verifiers = self._setup()
        receipt_b = _receipt(args_hex="c" * 64, result_hex="d" * 64, issued_at=1_789_000_000)
        self.assertNotEqual(receipt_a["receipt_id"], receipt_b["receipt_id"])
        verdict = verify_attestation(receipt_b, att, verifiers=verifiers, now=1_789_000_100)
        self.assertFalse(verdict.allowed)
        self.assertIn("replay", verdict.reason)

    def test_expired_quote_denied(self):
        attestor, receipt, att, verifiers = self._setup()
        binding = receipt_binding_digest(receipt)
        att = attestor.mint(measured_config=binding, issued_at=1_789_000_000, ttl_seconds=60)
        verdict = verify_attestation(receipt, att, verifiers=verifiers, now=1_789_000_000 + 61)
        self.assertFalse(verdict.allowed)
        self.assertIn("expired", verdict.reason)

    def test_quote_predating_receipt_denied(self):
        attestor = SoftwareAttestor(_secret("stale"))
        receipt = _receipt(issued_at=1_789_000_500)
        binding = receipt_binding_digest(receipt)
        att = attestor.mint(measured_config=binding, issued_at=1_789_000_000, ttl_seconds=3_600)
        verifiers = {"software": attestor.as_verifier()}
        verdict = verify_attestation(receipt, att, verifiers=verifiers, now=1_789_000_600,
                                     max_age_seconds=3_600)
        self.assertFalse(verdict.allowed)
        self.assertIn("predates", verdict.reason)

    def test_future_quote_denied(self):
        attestor, receipt, att, verifiers = self._setup()
        binding = receipt_binding_digest(receipt)
        att = attestor.mint(measured_config=binding, issued_at=1_789_000_000 + 10_000)
        verdict = verify_attestation(receipt, att, verifiers=verifiers, now=1_789_000_100)
        self.assertFalse(verdict.allowed)
        self.assertIn("future", verdict.reason)

    def test_too_old_quote_denied(self):
        attestor = SoftwareAttestor(_secret("old"))
        receipt = _receipt(issued_at=1_789_000_000)
        binding = receipt_binding_digest(receipt)
        att = attestor.mint(measured_config=binding, issued_at=1_789_000_000, ttl_seconds=100_000)
        verifiers = {"software": attestor.as_verifier()}
        verdict = verify_attestation(
            receipt, att, verifiers=verifiers, now=1_789_000_000 + 10_000, max_age_seconds=300
        )
        self.assertFalse(verdict.allowed)
        self.assertIn("max_age", verdict.reason)

    def test_tee_claim_without_verifier_denied(self):
        attestor, receipt, att, verifiers = self._setup()
        tee_att = dict(att)
        tee_att["evidence_kind"] = "tee"
        tee_att["emulated"] = False
        verdict = verify_attestation(receipt, tee_att, verifiers=verifiers, now=1_789_000_100)
        self.assertFalse(verdict.allowed)
        self.assertIn("no verifier registered", verdict.reason)

    def test_emulated_tee_claim_denied(self):
        attestor, receipt, att, verifiers = self._setup()
        tee_att = dict(att)
        tee_att["evidence_kind"] = "tee"  # emulated stays True
        verdict = verify_attestation(receipt, tee_att, verifiers=verifiers, now=1_789_000_100)
        self.assertFalse(verdict.allowed)
        self.assertIn("emulated", verdict.reason)

    def test_registered_tee_verifier_path(self):
        # The real-quote path: a platform verifier plugs in. Here a test
        # double plays the platform role (MAC under a separate tee secret).
        tee_secret = _secret("tee-platform")
        receipt = _receipt(issued_at=1_789_000_000)
        binding = receipt_binding_digest(receipt)
        envelope = {
            "kind": "tee",
            "measured_config": binding,
            "verifier_id": "test-dcap.v1",
            "issued_at": 1_789_000_000,
            "expires_at": 1_789_000_300,
        }
        mac = hashlib.sha256(
            tee_secret + json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        quote = dict(envelope)
        quote["mac"] = mac
        quote_bytes = json.dumps(quote, sort_keys=True, separators=(",", ":")).encode()

        def _tee_verify(qb: bytes, *, expected_binding: str) -> str:
            q = json.loads(qb.decode())
            expect = hashlib.sha256(
                tee_secret + json.dumps({k: v for k, v in q.items() if k != "mac"},
                                        sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()
            if q.get("mac") != expect:
                raise AttestedReceiptError("tee quote mac mismatch")
            return q["measured_config"]

        att = {
            "schema_version": ATTESTATION_SCHEMA_VERSION,
            "evidence_kind": "tee",
            "emulated": False,
            "quote_hex": quote_bytes.hex(),
            "quote_hash": hashlib.sha256(quote_bytes).hexdigest(),
            "verifier_id": "test-dcap.v1",
            "measured_config": binding,
            "issued_at": 1_789_000_000,
            "expires_at": 1_789_000_300,
        }
        verifiers = {"tee": QuoteVerifier(kind="tee", verifier_id="test-dcap.v1", verify=_tee_verify)}
        verdict = verify_attestation(receipt, att, verifiers=verifiers, now=1_789_000_100)
        self.assertTrue(verdict.allowed)
        self.assertEqual(verdict.evidence_kind, "tee")

    def test_quote_hash_mismatch_denied(self):
        _, receipt, att, verifiers = self._setup()
        bad = dict(att)
        bad["quote_hash"] = "0" * 64
        verdict = verify_attestation(receipt, bad, verifiers=verifiers, now=1_789_000_100)
        self.assertFalse(verdict.allowed)
        self.assertIn("quote_hash", verdict.reason)

    def test_malformed_attestation_raises(self):
        _, receipt, att, verifiers = self._setup()
        bad = dict(att)
        del bad["measured_config"]
        with self.assertRaises(AttestedReceiptError):
            verify_attestation(receipt, bad, verifiers=verifiers, now=1_789_000_100)
        with self.assertRaises(AttestedReceiptError):
            verify_attestation(receipt, {"nope": 1}, verifiers=verifiers, now=1_789_000_100)

    def test_verifier_id_mismatch_denied(self):
        _, receipt, att, verifiers = self._setup()
        bad = dict(att)
        bad["verifier_id"] = "someone.else"
        verdict = verify_attestation(receipt, bad, verifiers=verifiers, now=1_789_000_100)
        self.assertFalse(verdict.allowed)
        self.assertIn("verifier_id", verdict.reason)

    def test_malformed_inputs_raise(self):
        _, receipt, att, verifiers = self._setup()
        with self.assertRaises(AttestedReceiptError):
            verify_attestation(receipt, att, verifiers=verifiers, now=-1)
        with self.assertRaises(AttestedReceiptError):
            verify_attestation(receipt, att, verifiers=[], now=1_789_000_100)  # type: ignore[arg-type]
        with self.assertRaises(AttestedReceiptError):
            verify_attestation({"nope": 1}, att, verifiers=verifiers, now=1_789_000_100)


class AttachTests(unittest.TestCase):
    def test_attach_and_no_overwrite(self):
        attestor = SoftwareAttestor(_secret("attach"))
        receipt = _receipt()
        binding = receipt_binding_digest(receipt)
        att = attestor.mint(measured_config=binding, issued_at=receipt["issued_at"])
        out = attach_attestation(receipt, att)
        self.assertEqual(out["attestation"], att)
        self.assertEqual(out["receipt_id"], receipt["receipt_id"])  # id unchanged
        self.assertNotIn("attestation", receipt)  # original untouched
        with self.assertRaises(AttestedReceiptError):
            attach_attestation(out, att)

    def test_attach_rejects_malformed(self):
        with self.assertRaises(AttestedReceiptError):
            attach_attestation(_receipt(), {"nope": 1})

    def test_audit_event(self):
        attestor = SoftwareAttestor(_secret("audit"))
        receipt = _receipt()
        binding = receipt_binding_digest(receipt)
        att = attestor.mint(measured_config=binding, issued_at=receipt["issued_at"])
        verifiers = {"software": attestor.as_verifier()}
        verdict = verify_attestation(receipt, att, verifiers=verifiers, now=receipt["issued_at"] + 10)
        event = attestation_audit_event(verdict, receipt, att)
        self.assertEqual(event["event_type"], "attested_receipt.verified")
        self.assertEqual(event["receipt_id"], receipt["receipt_id"])
        self.assertEqual(event["quote_hash"], att["quote_hash"])
        denied = AttestationVerdict(allowed=False, reason="x", evidence_kind="tee",
                                    verifier_id="v", quote_hash="0" * 64)
        event2 = attestation_audit_event(denied, receipt)
        self.assertEqual(event2["event_type"], "attested_receipt.denied")


if __name__ == "__main__":
    unittest.main()
