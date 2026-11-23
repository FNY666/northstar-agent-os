"""Tests for memory_capability.py -- capability-token memory admission."""

import hashlib
import unittest

import ed25519

from memory_capability import (
    ADMITTABLE_CATEGORIES,
    CATEGORY_CREDENTIAL,
    KNOWN_CATEGORIES,
    MEMORY_CAPABILITY_VERSION,
    PROHIBITED_INFERENCES,
    REASON_ADMITTED,
    REASON_CATEGORY_NOT_IN_TOKEN,
    REASON_CREDENTIAL_NEVER,
    REASON_EXPIRED,
    REASON_INVALID_SIGNATURE,
    REASON_MALFORMED,
    REASON_MISSING_TOKEN,
    REASON_PROHIBITED_INFERENCE,
    REASON_UNKNOWN_CATEGORY,
    SCHEMA_PIN,
    AdmissionDecision,
    CapabilityAdmission,
    CapabilityToken,
    issue_token,
    verify_token,
)


def _issuer():
    seed = hashlib.sha256(b"test issuer key").digest()
    return seed, ed25519.public_key(seed)


def _gate():
    seed, pub = _issuer()
    return CapabilityAdmission(pub), seed


class TestVersion(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(MEMORY_CAPABILITY_VERSION, "memory-capability.v1")
        self.assertEqual(SCHEMA_PIN, "northstar.memory-capability.v1")
        self.assertEqual(CapabilityAdmission.version(), "memory-capability.v1")


class TestIssueToken(unittest.TestCase):
    def test_issue_ok(self):
        seed, _ = _issuer()
        t = issue_token({"preference", "fact"}, 100, seed)
        self.assertTrue(t.token_id.startswith("ctok-"))
        self.assertEqual(t.categories, frozenset({"preference", "fact"}))
        self.assertEqual(t.expires_seq, 100)
        self.assertEqual(len(t.signature), 64)

    def test_issue_explicit_token_id(self):
        seed, _ = _issuer()
        t = issue_token({"fact"}, 50, seed, token_id="ctok-custom-1")
        self.assertEqual(t.token_id, "ctok-custom-1")

    def test_issue_rejects_empty_categories(self):
        seed, _ = _issuer()
        with self.assertRaises(ValueError):
            issue_token(set(), 100, seed)

    def test_issue_rejects_credential_category(self):
        seed, _ = _issuer()
        with self.assertRaises(ValueError):
            issue_token({"fact", "credential"}, 100, seed)

    def test_issue_rejects_prohibited_inference(self):
        seed, _ = _issuer()
        for cat in PROHIBITED_INFERENCES:
            with self.assertRaises(ValueError):
                issue_token({"fact", cat}, 100, seed)

    def test_issue_rejects_unknown_category(self):
        seed, _ = _issuer()
        with self.assertRaises(ValueError):
            issue_token({"nonsense"}, 100, seed)

    def test_issue_rejects_bad_key(self):
        with self.assertRaises(ValueError):
            issue_token({"fact"}, 100, b"too-short")

    def test_issue_rejects_zero_expiry(self):
        seed, _ = _issuer()
        with self.assertRaises(ValueError):
            issue_token({"fact"}, 0, seed)

    def test_issue_rejects_negative_expiry(self):
        seed, _ = _issuer()
        with self.assertRaises(ValueError):
            issue_token({"fact"}, -5, seed)

    def test_token_frozen(self):
        seed, _ = _issuer()
        t = issue_token({"fact"}, 100, seed)
        with self.assertRaises(Exception):
            t.expires_seq = 999


class TestVerifyToken(unittest.TestCase):
    def test_verify_ok(self):
        seed, pub = _issuer()
        t = issue_token({"fact"}, 100, seed)
        self.assertTrue(verify_token(t, pub))

    def test_verify_wrong_key(self):
        seed, _ = _issuer()
        other = hashlib.sha256(b"other key").digest()
        t = issue_token({"fact"}, 100, seed)
        self.assertFalse(verify_token(t, ed25519.public_key(other)))

    def test_verify_tampered_categories(self):
        seed, pub = _issuer()
        t = issue_token({"fact"}, 100, seed)
        tampered = CapabilityToken(
            token_id=t.token_id,
            categories=frozenset({"fact", "preference"}),
            expires_seq=t.expires_seq,
            signature=t.signature,
        )
        self.assertFalse(verify_token(tampered, pub))

    def test_verify_tampered_expiry(self):
        seed, pub = _issuer()
        t = issue_token({"fact"}, 100, seed)
        tampered = CapabilityToken(
            token_id=t.token_id,
            categories=t.categories,
            expires_seq=9999,
            signature=t.signature,
        )
        self.assertFalse(verify_token(tampered, pub))

    def test_verify_non_token_returns_false(self):
        _, pub = _issuer()
        self.assertFalse(verify_token("not-a-token", pub))
        self.assertFalse(verify_token(None, pub))

    def test_verify_bad_key_length_returns_false(self):
        seed, _ = _issuer()
        t = issue_token({"fact"}, 100, seed)
        self.assertFalse(verify_token(t, b"short"))

    def test_verify_schema_bound(self):
        seed, pub = _issuer()
        t = issue_token({"fact"}, 100, seed)
        self.assertEqual(t.body()["schema"], SCHEMA_PIN)


class TestAdmission(unittest.TestCase):
    def test_admit_happy_path(self):
        gate, seed = _gate()
        t = issue_token({"preference"}, 100, seed)
        self.assertTrue(gate.admit_write("preference", "likes tea", t, 10))

    def test_deny_wrong_key_signature(self):
        gate, seed = _gate()
        other = hashlib.sha256(b"other").digest()
        t = issue_token({"preference"}, 100, other)
        self.assertFalse(gate.admit_write("preference", "x", t, 10))
        self.assertEqual(gate.denied()[-1].reason, REASON_INVALID_SIGNATURE)

    def test_deny_missing_token(self):
        gate, _ = _gate()
        self.assertFalse(gate.admit_write("preference", "x", None, 10))
        self.assertEqual(gate.denied()[-1].reason, REASON_MISSING_TOKEN)

    def test_deny_expired_strict(self):
        gate, seed = _gate()
        t = issue_token({"preference"}, 100, seed)
        self.assertTrue(gate.admit_write("preference", "x", t, 99))
        self.assertFalse(gate.admit_write("preference", "x", t, 100))
        self.assertEqual(gate.denied()[-1].reason, REASON_EXPIRED)

    def test_deny_category_not_in_token(self):
        gate, seed = _gate()
        t = issue_token({"preference"}, 100, seed)
        self.assertFalse(gate.admit_write("fact", "x", t, 10))
        self.assertEqual(gate.denied()[-1].reason, REASON_CATEGORY_NOT_IN_TOKEN)

    def test_deny_credential_even_with_token(self):
        gate, seed = _gate()
        t = issue_token({"preference", "fact"}, 100, seed)
        self.assertFalse(gate.admit_write("credential", "pw", t, 10))
        self.assertEqual(gate.denied()[-1].reason, REASON_CREDENTIAL_NEVER)

    def test_deny_prohibited_inference_even_with_token(self):
        gate, seed = _gate()
        t = issue_token(set(ADMITTABLE_CATEGORIES), 100, seed)
        for cat in PROHIBITED_INFERENCES:
            self.assertFalse(gate.admit_write(cat, "x", t, 10))
        reasons = {d.reason for d in gate.denied()}
        self.assertIn(REASON_PROHIBITED_INFERENCE, reasons)

    def test_deny_unknown_category(self):
        gate, seed = _gate()
        t = issue_token({"fact"}, 100, seed)
        self.assertFalse(gate.admit_write("nonsense", "x", t, 10))
        self.assertEqual(gate.denied()[-1].reason, REASON_UNKNOWN_CATEGORY)

    def test_deny_malformed_category(self):
        gate, seed = _gate()
        t = issue_token({"fact"}, 100, seed)
        self.assertFalse(gate.admit_write("", "x", t, 10))
        self.assertFalse(gate.admit_write(None, "x", t, 10))
        self.assertEqual(gate.denied()[-1].reason, REASON_MALFORMED)

    def test_deny_empty_content(self):
        gate, seed = _gate()
        t = issue_token({"fact"}, 100, seed)
        self.assertFalse(gate.admit_write("fact", "", t, 10))

    def test_deny_unverifiable_seq(self):
        gate, seed = _gate()
        t = issue_token({"fact"}, 100, seed)
        self.assertFalse(gate.admit_write("fact", "x", t, None))

    def test_expired_static(self):
        seed, _ = _issuer()
        t = issue_token({"fact"}, 100, seed)
        # strict expiry: valid while current_seq < expires_seq
        self.assertFalse(CapabilityAdmission.expired(t, 99))
        self.assertTrue(CapabilityAdmission.expired(t, 100))
        self.assertTrue(CapabilityAdmission.expired(t, 101))
        self.assertTrue(CapabilityAdmission.expired("junk", 10))

    def test_decision_log_records_token_id(self):
        gate, seed = _gate()
        t = issue_token({"fact"}, 100, seed)
        gate.admit_write("fact", "x", t, 10)
        d = gate.decisions()[-1]
        self.assertIsInstance(d, AdmissionDecision)
        self.assertTrue(d.admitted)
        self.assertEqual(d.reason, REASON_ADMITTED)
        self.assertEqual(d.token_id, t.token_id)

    def test_gate_rejects_bad_issuer_key(self):
        with self.assertRaises(ValueError):
            CapabilityAdmission(b"short")

    def test_known_categories_cover_vocabulary(self):
        self.assertIn(CATEGORY_CREDENTIAL, KNOWN_CATEGORIES)
        for c in ADMITTABLE_CATEGORIES:
            self.assertIn(c, KNOWN_CATEGORIES)
        for c in PROHIBITED_INFERENCES:
            self.assertIn(c, KNOWN_CATEGORIES)


if __name__ == "__main__":
    unittest.main()
