"""Tests for code_signer: Sigstore-shaped signing bookkeeping, simulated."""

from __future__ import annotations

import ast
import unittest
from pathlib import Path

from code_signer import (
    AUDIT_SCHEMA,
    CODE_SIGNER_SCHEMA,
    CODE_SIGNER_VERSION,
    CodeSigner,
    CodeSignerError,
    DuplicateKeyError,
    RevokedKeyError,
    SeqOrderError,
    UnknownIssuerError,
    UnknownKeyError,
    ValidationError,
    code_signer_audit_event,
    main,
)

GOOD_PUB = "ab" * 32
GOOD_SEC = "cd" * 32


class TestPins(unittest.TestCase):
    def test_version_pins(self):
        self.assertEqual(CODE_SIGNER_VERSION, "code-signer.v1")
        self.assertEqual(CODE_SIGNER_SCHEMA, "northstar.code-signer.v1")


class TestKeyLifecycle(unittest.TestCase):
    def test_register_roundtrip(self):
        s = CodeSigner()
        rec = s.register_key("k1", GOOD_PUB, GOOD_SEC, 0)
        self.assertTrue(rec.pin.startswith("sha256:"))
        self.assertEqual(s.key_ids(), ("k1",))

    def test_duplicate_key_refused(self):
        s = CodeSigner()
        s.register_key("k1", GOOD_PUB, GOOD_SEC, 0)
        with self.assertRaises(DuplicateKeyError):
            s.register_key("k1", GOOD_PUB, GOOD_SEC, 1)

    def test_bad_hex_refused(self):
        s = CodeSigner()
        with self.assertRaises(ValidationError):
            s.register_key("k1", "not-hex", GOOD_SEC, 0)

    def test_revoke_terminal(self):
        s = CodeSigner()
        s.register_key("k1", GOOD_PUB, GOOD_SEC, 0)
        rec = s.revoke("k1", 1)
        self.assertTrue(s.is_revoked("k1"))
        self.assertTrue(rec.pin.startswith("sha256:"))
        with self.assertRaises(CodeSignerError):
            s.revoke("k1", 2)


class TestKeyedSigning(unittest.TestCase):
    def _signed(self, seq_start=0):
        s = CodeSigner()
        s.register_key("k1", GOOD_PUB, GOOD_SEC, seq_start)
        sig = s.sign("app-1", "sha256:aa", "k1", seq_start + 1)
        return s, sig

    def test_sign_verify_roundtrip(self):
        s, sig = self._signed()
        self.assertTrue(sig.pin.startswith("sha256:"))
        rep = s.verify(sig.signature_id, "sha256:aa", 2)
        self.assertTrue(rep.valid)
        self.assertEqual(rep.reason, "ok")

    def test_verify_digest_mismatch_is_data(self):
        s, sig = self._signed()
        rep = s.verify(sig.signature_id, "sha256:bb", 2)
        self.assertFalse(rep.valid)
        self.assertEqual(rep.reason, "digest-mismatch")

    def test_verify_unknown_signature_is_data(self):
        s = CodeSigner()
        rep = s.verify("sig-99", "sha256:aa", 0)
        self.assertFalse(rep.valid)
        self.assertEqual(rep.reason, "unknown-signature")

    def test_sign_unknown_key_raises(self):
        s = CodeSigner()
        with self.assertRaises(UnknownKeyError):
            s.sign("app-1", "sha256:aa", "nope", 0)

    def test_sign_revoked_key_raises(self):
        s, sig = self._signed()
        s.revoke("k1", 2)
        with self.assertRaises(RevokedKeyError):
            s.sign("app-2", "sha256:cc", "k1", 3)
        rep = s.verify(sig.signature_id, "sha256:aa", 4)
        self.assertFalse(rep.valid)
        self.assertEqual(rep.reason, "key-revoked")

    def test_seq_order_enforced(self):
        s = CodeSigner()
        s.register_key("k1", GOOD_PUB, GOOD_SEC, 5)
        with self.assertRaises(SeqOrderError):
            s.sign("app-1", "sha256:aa", "k1", 5)
        with self.assertRaises(CodeSignerError):
            s.sign("app-1", "sha256:aa", "k1", True)


class TestKeylessSigning(unittest.TestCase):
    def test_keyless_roundtrip(self):
        s = CodeSigner()
        kls = s.keyless(
            "alice@example.com",
            "app-1",
            "sha256:aa",
            "https://accounts.google.com",
            0,
        )
        self.assertTrue(kls.ephemeral_key_id.startswith("eph-"))
        rep = s.verify_keyless(kls.signature_id, "sha256:aa", 1)
        self.assertTrue(rep.valid)
        self.assertEqual(rep.reason, "ok")

    def test_keyless_digest_mismatch_is_data(self):
        s = CodeSigner()
        kls = s.keyless(
            "alice@example.com",
            "app-1",
            "sha256:aa",
            "https://accounts.google.com",
            0,
        )
        rep = s.verify_keyless(kls.signature_id, "sha256:bb", 1)
        self.assertFalse(rep.valid)
        self.assertEqual(rep.reason, "digest-mismatch")

    def test_unknown_issuer_refused(self):
        s = CodeSigner()
        with self.assertRaises(UnknownIssuerError):
            s.keyless(
                "alice@example.com",
                "app-1",
                "sha256:aa",
                "https://evil.example.com",
                0,
            )


class TestAudit(unittest.TestCase):
    def test_audit_shape_and_bad_kind(self):
        ev = code_signer_audit_event("signed", 3, signature_id="sig-1")
        self.assertEqual(ev["schema"], AUDIT_SCHEMA)
        self.assertEqual(ev["audit_seq"], 3)
        with self.assertRaises(CodeSignerError):
            code_signer_audit_event("bogus-kind", 0)

    def test_audit_bans_key_material(self):
        with self.assertRaises(CodeSignerError):
            code_signer_audit_event("key-registered", 0, secret_hex="deadbeef")


class TestStdlibOnly(unittest.TestCase):
    def test_stdlib_only(self):
        src = Path(__file__).parent.parent.joinpath("code_signer.py").read_text()
        tree = ast.parse(src)
        allowed = {
            "hashlib",
            "hmac",
            "re",
            "threading",
            "dataclasses",
            "typing",
            "__future__",
            "json",
            "canonical_json",  # the standard guarded canonicalizer import
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    self.assertIn(a.name.split(".")[0], allowed)
            elif isinstance(node, ast.ImportFrom):
                self.assertIn((node.module or "").split(".")[0], allowed)

    def test_main_self_check(self):
        main()


if __name__ == "__main__":
    unittest.main()
