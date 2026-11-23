"""Tests for hsm_interface: simulated HSM keygen/sign/decrypt boundary."""

import sys
import unittest

sys.path.insert(0, "..")

from hsm_interface import (
    SCHEMA_PIN,
    HSM,
    HSMError,
    HSM_INTERFACE_VERSION,
    Ciphertext,
    IntegrityError,
    KeyHandle,
    PublicKey,
    Signature,
    hsm_audit_event,
)


def _hsm(label="test"):
    return HSM(label)


class TestPins(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(HSM_INTERFACE_VERSION, "hsm-interface.v1")

    def test_schema_pin(self):
        self.assertEqual(SCHEMA_PIN, "northstar.hsm-interface.v1")


class TestGenerateKey(unittest.TestCase):
    def test_happy_path(self):
        h = _hsm().generate_key("ed25519-sim", 1)
        self.assertIsInstance(h, KeyHandle)
        self.assertTrue(h.key_id.startswith("key-"))

    def test_frozen_handle(self):
        h = _hsm().generate_key("hmac-sha256", 1)
        with self.assertRaises(Exception):
            h.key_id = "x"  # type: ignore[misc]

    def test_all_algorithms(self):
        hsm = _hsm()
        for alg in ("ed25519-sim", "hmac-sha256", "rsa-oaep-sim", "aes-256-gcm-sim"):
            handle = hsm.generate_key(alg, 1)
            self.assertEqual(handle.algorithm, alg)

    def test_unknown_algorithm(self):
        with self.assertRaises(HSMError):
            _hsm().generate_key("des", 1)

    def test_bad_seq(self):
        hsm = _hsm()
        for bad in (-1, True, "1", 1.5):
            with self.assertRaises(HSMError):
                hsm.generate_key("ed25519-sim", bad)

    def test_keys_distinct(self):
        hsm = _hsm()
        a = hsm.generate_key("ed25519-sim", 1)
        b = hsm.generate_key("ed25519-sim", 2)
        self.assertNotEqual(a.key_id, b.key_id)
        self.assertEqual(hsm.key_count(), 2)

    def test_label_isolation(self):
        a = HSM("one").generate_key("ed25519-sim", 1)
        b = HSM("two").generate_key("ed25519-sim", 1)
        self.assertNotEqual(a.key_id, b.key_id)

    def test_material_pin_shape(self):
        h = _hsm().generate_key("ed25519-sim", 1)
        self.assertTrue(h.material_pin.startswith("sha256:"))
        self.assertEqual(len(h.material_pin), 7 + 64)

    def test_handle_as_dict(self):
        h = _hsm().generate_key("ed25519-sim", 1)
        d = h.as_dict()
        self.assertEqual(d["schema"], SCHEMA_PIN)
        self.assertEqual(d["key_id"], h.key_id)


class TestSignVerify(unittest.TestCase):
    def test_sign_happy_path(self):
        hsm = _hsm()
        h = hsm.generate_key("ed25519-sim", 1)
        sig = hsm.sign(h, b"hello", 2)
        self.assertIsInstance(sig, Signature)
        self.assertEqual(sig.key_id, h.key_id)
        self.assertTrue(sig.message_pin.startswith("sha256:"))

    def test_sign_deterministic(self):
        hsm = _hsm()
        h = hsm.generate_key("ed25519-sim", 1)
        a = hsm.sign(h, b"hello", 2)
        b = hsm.sign(h, b"hello", 3)
        self.assertEqual(a.sig, b.sig)

    def test_verify_with_public(self):
        hsm = _hsm()
        h = hsm.generate_key("ed25519-sim", 1)
        pub = hsm.export_public(h, 2)
        sig = hsm.sign(h, b"hello", 3)
        self.assertTrue(hsm.verify_signature(pub, b"hello", sig))
        self.assertFalse(hsm.verify_signature(pub, b"goodbye", sig))

    def test_hmac_sign(self):
        hsm = _hsm()
        h = hsm.generate_key("hmac-sha256", 1)
        sig = hsm.sign(h, b"ping", 2)
        self.assertEqual(len(sig.sig), 32)

    def test_sign_wrong_algorithm(self):
        hsm = _hsm()
        h = hsm.generate_key("aes-256-gcm-sim", 1)
        with self.assertRaises(HSMError):
            hsm.sign(h, b"hello", 2)

    def test_sign_bad_message_type(self):
        hsm = _hsm()
        h = hsm.generate_key("ed25519-sim", 1)
        with self.assertRaises(TypeError):
            hsm.sign(h, "hello", 2)  # type: ignore[arg-type]

    def test_sign_empty_message(self):
        hsm = _hsm()
        h = hsm.generate_key("ed25519-sim", 1)
        with self.assertRaises(HSMError):
            hsm.sign(h, b"", 2)

    def test_sign_unknown_handle(self):
        hsm = _hsm()
        other = _hsm().generate_key("ed25519-sim", 1)
        with self.assertRaises(HSMError):
            hsm.sign(other, b"hello", 2)

    def test_export_public_symmetric_refused(self):
        hsm = _hsm()
        h = hsm.generate_key("hmac-sha256", 1)
        with self.assertRaises(HSMError):
            hsm.export_public(h, 2)

    def test_verify_cross_instance_false(self):
        hsm_a, hsm_b = _hsm(), _hsm()
        h = hsm_a.generate_key("ed25519-sim", 1)
        pub = hsm_a.export_public(h, 2)
        sig = hsm_a.sign(h, b"hello", 3)
        self.assertFalse(hsm_b.verify_signature(pub, b"hello", sig))


class TestEncryptDecrypt(unittest.TestCase):
    def test_asymmetric_roundtrip(self):
        hsm = _hsm()
        h = hsm.generate_key("rsa-oaep-sim", 1)
        pub = hsm.export_public(h, 2)
        ct = hsm.encrypt(pub, b"payload", 3)
        self.assertIsInstance(ct, Ciphertext)
        self.assertEqual(hsm.decrypt(h, ct, 4), b"payload")

    def test_symmetric_roundtrip(self):
        hsm = _hsm()
        h = hsm.generate_key("aes-256-gcm-sim", 1)
        ct = hsm.encrypt(h, b"secret-data", 2)
        self.assertEqual(hsm.decrypt(h, ct, 3), b"secret-data")

    def test_ciphertext_hides_plaintext(self):
        hsm = _hsm()
        h = hsm.generate_key("aes-256-gcm-sim", 1)
        ct = hsm.encrypt(h, b"secret-data", 2)
        self.assertNotIn(b"secret-data", ct.body)

    def test_tamper_fails_closed(self):
        hsm = _hsm()
        h = hsm.generate_key("aes-256-gcm-sim", 1)
        ct = hsm.encrypt(h, b"secret-data", 2)
        tampered = Ciphertext(
            key_id=ct.key_id,
            algorithm=ct.algorithm,
            nonce=ct.nonce,
            body=bytes([ct.body[0] ^ 1]) + ct.body[1:],
            tag=ct.tag,
        )
        with self.assertRaises(IntegrityError):
            hsm.decrypt(h, tampered, 3)

    def test_decrypt_wrong_key(self):
        hsm = _hsm()
        a = hsm.generate_key("aes-256-gcm-sim", 1)
        b = hsm.generate_key("aes-256-gcm-sim", 2)
        ct = hsm.encrypt(a, b"data", 3)
        with self.assertRaises(HSMError):
            hsm.decrypt(b, ct, 4)

    def test_decrypt_with_signing_key(self):
        hsm = _hsm()
        h = hsm.generate_key("ed25519-sim", 1)
        ct = Ciphertext(
            key_id=h.key_id, algorithm="ed25519-sim", nonce=0,
            body=b"x", tag=b"0" * 16,
        )
        with self.assertRaises(HSMError):
            hsm.decrypt(h, ct, 2)

    def test_encrypt_nonce_advances(self):
        hsm = _hsm()
        h = hsm.generate_key("aes-256-gcm-sim", 1)
        ct1 = hsm.encrypt(h, b"same", 2)
        ct2 = hsm.encrypt(h, b"same", 3)
        self.assertNotEqual(ct1.nonce, ct2.nonce)
        self.assertNotEqual(ct1.body, ct2.body)
        self.assertEqual(hsm.decrypt(h, ct2, 4), b"same")


class TestAuditEvent(unittest.TestCase):
    def test_shapes(self):
        ev = hsm_audit_event("key-generated", 5, key_id="key-1")
        self.assertEqual(ev["schema"], "audit.ndjson/1")
        self.assertEqual(ev["kind"], "hsm-interface.key-generated")
        self.assertEqual(ev["module"], SCHEMA_PIN)
        self.assertEqual(ev["seq"], 5)
        self.assertEqual(ev["key_id"], "key-1")

    def test_no_key_id(self):
        ev = hsm_audit_event("rejected", 0)
        self.assertNotIn("key_id", ev)

    def test_bad_kind(self):
        with self.assertRaises(ValueError):
            hsm_audit_event("exploded", 1)

    def test_bad_seq(self):
        with self.assertRaises(HSMError):
            hsm_audit_event("signed", -1)


class TestMain(unittest.TestCase):
    def test_main(self):
        from hsm_interface import main

        main()  # asserts internally


if __name__ == "__main__":
    unittest.main()
