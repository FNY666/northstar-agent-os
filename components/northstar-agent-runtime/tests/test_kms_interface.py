"""Targeted tests for kms_interface.py."""

import unittest

from kms_interface import (
    KMS,
    Key,
    Envelope,
    RotationRecord,
    RevocationRecord,
    KMSError,
    DuplicateAliasError,
    UnknownAliasError,
    KMSDeniedError,
    EnvelopeIntegrityError,
    kms_audit_event,
    __version__,
    __schema__,
)


class TestPins(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(__version__, "kms-interface.v1")

    def test_schema_pin(self):
        self.assertEqual(__schema__, "northstar.kms-interface.v1")


class TestCreate(unittest.TestCase):
    def test_create_key(self):
        kms = KMS()
        key = kms.create_key("a", "signing", 0)
        self.assertEqual(key.alias, "a")
        self.assertEqual(key.version, 1)
        self.assertEqual(key.state, "active")
        self.assertTrue(key.public_pin.startswith("sha256:"))

    def test_duplicate_alias_refused(self):
        kms = KMS()
        kms.create_key("a", "signing", 0)
        with self.assertRaises(DuplicateAliasError):
            kms.create_key("a", "signing", 1)

    def test_empty_alias_refused(self):
        kms = KMS()
        with self.assertRaises(KMSError):
            kms.create_key("", "signing", 0)

    def test_bad_seq_refused(self):
        kms = KMS()
        for bad in (-1, True, "1", None):
            with self.assertRaises(KMSError):
                kms.create_key("a", "signing", bad)

    def test_key_as_dict(self):
        kms = KMS()
        key = kms.create_key("a", "signing", 3)
        d = key.as_dict()
        self.assertEqual(d["module"], "kms-interface.v1")
        self.assertEqual(d["schema"], "northstar.kms-interface.v1")
        self.assertEqual(d["created_seq"], 3)


class TestRotate(unittest.TestCase):
    def test_rotate(self):
        kms = KMS()
        kms.create_key("a", "signing", 0)
        rec = kms.rotate_key("a", 1)
        self.assertIsInstance(rec, RotationRecord)
        self.assertEqual(rec.old_version, 1)
        self.assertEqual(rec.new_version, 2)
        self.assertEqual(kms.current_key("a").version, 2)
        self.assertEqual(kms.current_key("a").state, "active")

    def test_old_version_superseded(self):
        kms = KMS()
        kms.create_key("a", "signing", 0)
        kms.rotate_key("a", 1)
        versions = kms.describe("a")
        self.assertEqual(versions[0].state, "superseded")
        self.assertEqual(versions[1].state, "active")

    def test_rotate_unknown_refused(self):
        kms = KMS()
        with self.assertRaises(UnknownAliasError):
            kms.rotate_key("nope", 1)

    def test_rotate_revoked_refused(self):
        kms = KMS()
        kms.create_key("a", "signing", 0)
        kms.revoke_key("a", 1)
        with self.assertRaises(KMSDeniedError):
            kms.rotate_key("a", 2)


class TestRevoke(unittest.TestCase):
    def test_revoke(self):
        kms = KMS()
        kms.create_key("a", "signing", 0)
        rec = kms.revoke_key("a", 1)
        self.assertIsInstance(rec, RevocationRecord)
        for k in kms.describe("a"):
            self.assertEqual(k.state, "revoked")

    def test_revoke_marks_all_versions(self):
        kms = KMS()
        kms.create_key("a", "signing", 0)
        kms.rotate_key("a", 1)
        kms.revoke_key("a", 2)
        states = [k.state for k in kms.describe("a")]
        self.assertEqual(states, ["revoked", "revoked"])

    def test_revoke_unknown_refused(self):
        kms = KMS()
        with self.assertRaises(UnknownAliasError):
            kms.revoke_key("nope", 1)


class TestEncryptDecrypt(unittest.TestCase):
    def test_roundtrip(self):
        kms = KMS()
        kms.create_key("a", "enc", 0)
        env = kms.encrypt("a", b"payload", 1)
        self.assertIsInstance(env, Envelope)
        self.assertEqual(kms.decrypt(env, 2), b"payload")

    def test_empty_plaintext_refused(self):
        # Envelope requires non-empty ciphertext, so empty plaintext is
        # fail-closed rather than sealed silently.
        kms = KMS()
        kms.create_key("a", "enc", 0)
        with self.assertRaises(KMSError):
            kms.encrypt("a", b"", 1)

    def test_ciphertext_differs_from_plaintext(self):
        kms = KMS()
        kms.create_key("a", "enc", 0)
        env = kms.encrypt("a", b"payload", 1)
        self.assertNotEqual(env.ciphertext, b"payload")

    def test_encrypt_unknown_alias(self):
        kms = KMS()
        with self.assertRaises(UnknownAliasError):
            kms.encrypt("nope", b"x", 1)

    def test_encrypt_revoked_refused(self):
        kms = KMS()
        kms.create_key("a", "enc", 0)
        kms.revoke_key("a", 1)
        with self.assertRaises(KMSDeniedError):
            kms.encrypt("a", b"x", 2)

    def test_decrypt_revoked_refused(self):
        kms = KMS()
        kms.create_key("a", "enc", 0)
        env = kms.encrypt("a", b"x", 1)
        kms.revoke_key("a", 2)
        with self.assertRaises(KMSDeniedError):
            kms.decrypt(env, 3)

    def test_superseded_still_decrypts(self):
        kms = KMS()
        kms.create_key("a", "enc", 0)
        old_env = kms.encrypt("a", b"old", 1)
        kms.rotate_key("a", 2)
        self.assertEqual(kms.decrypt(old_env, 3), b"old")

    def test_encrypt_uses_current_version(self):
        kms = KMS()
        kms.create_key("a", "enc", 0)
        kms.rotate_key("a", 1)
        env = kms.encrypt("a", b"new", 2)
        self.assertEqual(env.version, 2)

    def test_tampered_ciphertext_refused(self):
        kms = KMS()
        kms.create_key("a", "enc", 0)
        env = kms.encrypt("a", b"payload", 1)
        tampered = Envelope(alias=env.alias, version=env.version,
                            nonce=env.nonce,
                            ciphertext=b"\x00" + env.ciphertext[1:],
                            tag=env.tag, seq=env.seq)
        with self.assertRaises(EnvelopeIntegrityError):
            kms.decrypt(tampered, 2)

    def test_tampered_tag_refused(self):
        kms = KMS()
        kms.create_key("a", "enc", 0)
        env = kms.encrypt("a", b"payload", 1)
        tampered = Envelope(alias=env.alias, version=env.version,
                            nonce=env.nonce, ciphertext=env.ciphertext,
                            tag=b"\x00" * len(env.tag), seq=env.seq)
        with self.assertRaises(EnvelopeIntegrityError):
            kms.decrypt(tampered, 2)

    def test_deterministic_seal_reproducible(self):
        k1, k2 = KMS(), KMS()
        k1.create_key("a", "enc", 0)
        k2.create_key("a", "enc", 0)
        e1 = k1.encrypt("a", b"x", 1)
        e2 = k2.encrypt("a", b"x", 1)
        self.assertEqual(e1.ciphertext, e2.ciphertext)

    def test_nonces_advance(self):
        kms = KMS()
        kms.create_key("a", "enc", 0)
        e1 = kms.encrypt("a", b"x", 1)
        e2 = kms.encrypt("a", b"x", 2)
        self.assertNotEqual(e1.nonce, e2.nonce)


class TestValidation(unittest.TestCase):
    def test_plaintext_must_be_bytes(self):
        kms = KMS()
        kms.create_key("a", "enc", 0)
        with self.assertRaises(KMSError):
            kms.encrypt("a", "not-bytes", 1)

    def test_envelope_type_checked(self):
        kms = KMS()
        with self.assertRaises(KMSError):
            kms.decrypt({"not": "an envelope"}, 1)

    def test_guardrail(self):
        kms = KMS()
        kms.create_key("a", "enc", 0)
        with self.assertRaises(KMSError):
            kms.encrypt("a", b"x" * ((1 << 20) + 1), 1)

    def test_frozen_key(self):
        import dataclasses
        kms = KMS()
        key = kms.create_key("a", "enc", 0)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            key.state = "revoked"  # type: ignore

    def test_envelope_as_dict_shape(self):
        kms = KMS()
        kms.create_key("a", "enc", 0)
        env = kms.encrypt("a", b"x", 1)
        d = env.as_dict()
        self.assertIn("digest", d)
        self.assertEqual(d["module"], "kms-interface.v1")


class TestAuditEvent(unittest.TestCase):
    def test_event_shape(self):
        ev = kms_audit_event("key-created", 7, alias="a", version=1)
        self.assertEqual(ev["event"], "kms-interface")
        self.assertEqual(ev["kind"], "key-created")
        self.assertEqual(ev["audit_seq"], 7)
        self.assertEqual(ev["schema"], "audit.ndjson/1")
        self.assertEqual(ev["alias"], "a")

    def test_bad_kind_refused(self):
        with self.assertRaises(ValueError):
            kms_audit_event("nonsense", 0)

    def test_bad_seq_refused(self):
        with self.assertRaises(ValueError):
            kms_audit_event("encrypted", -1)

    def test_all_kinds(self):
        for kind in ("key-created", "key-rotated", "key-revoked",
                     "encrypted", "decrypted", "encrypt-refused",
                     "decrypt-refused"):
            ev = kms_audit_event(kind, 0)
            self.assertEqual(ev["kind"], kind)


class TestMain(unittest.TestCase):
    def test_main_self_check(self):
        import kms_interface
        kms_interface.main()


if __name__ == "__main__":
    unittest.main()
