"""Tests for pqc_kem (simulated post-quantum KEM interface)."""

import unittest

import pqc_kem
from pqc_kem import (
    PARAM_SETS,
    DecapsulationError,
    Encapsulation,
    KeyPair,
    PQCKEM,
    PqcKemError,
    pqc_kem_audit_event,
)


class TestPinsAndParams(unittest.TestCase):
    def test_version_and_schema_pins(self):
        self.assertEqual(pqc_kem.KEM_VERSION, "pqc-kem.v1")
        self.assertEqual(pqc_kem.SCHEMA_PIN, "northstar.pqc-kem.v1")

    def test_param_sets_cover_nist_levels(self):
        self.assertEqual(PARAM_SETS["ml-kem-512"]["nist_level"], 1)
        self.assertEqual(PARAM_SETS["ml-kem-768"]["nist_level"], 3)
        self.assertEqual(PARAM_SETS["ml-kem-1024"]["nist_level"], 5)
        for name, meta in PARAM_SETS.items():
            self.assertEqual(meta["shared_secret_bytes"], 32)

    def test_nist_level_property(self):
        self.assertEqual(PQCKEM("ml-kem-512").nist_level, 1)
        self.assertEqual(PQCKEM().nist_level, 3)  # default 768

    def test_unknown_param_set_rejected(self):
        with self.assertRaises(PqcKemError):
            PQCKEM("kyber-999")
        with self.assertRaises(PqcKemError):
            PQCKEM("")
        with self.assertRaises(PqcKemError):
            PQCKEM(None)  # type: ignore[arg-type]
        with self.assertRaises(PqcKemError):
            PQCKEM(768)  # type: ignore[arg-type]


class TestKeygen(unittest.TestCase):
    def test_keygen_shape(self):
        kp = PQCKEM().generate_keypair(b"seed-1")
        self.assertEqual(len(kp.public_key), 32)
        self.assertEqual(len(kp.secret_key), 32)
        self.assertEqual(kp.param_set, "ml-kem-768")
        self.assertEqual(kp.schema, pqc_kem.SCHEMA_PIN)

    def test_keygen_deterministic(self):
        a = PQCKEM().generate_keypair(b"same-seed")
        b = PQCKEM().generate_keypair(b"same-seed")
        self.assertEqual(a.public_key, b.public_key)
        self.assertEqual(a.secret_key, b.secret_key)

    def test_keygen_seed_distinctness(self):
        a = PQCKEM().generate_keypair(b"seed-a")
        b = PQCKEM().generate_keypair(b"seed-b")
        self.assertNotEqual(a.public_key, b.public_key)
        self.assertNotEqual(a.secret_key, b.secret_key)

    def test_keygen_pk_derives_from_sk(self):
        kp = PQCKEM().generate_keypair(b"seed")
        # re-derive: pk = H(domain || "kem-pk" || sk)
        expected = pqc_kem._public_key(kp.secret_key)
        self.assertEqual(kp.public_key, expected)

    def test_keygen_seed_validation(self):
        kem = PQCKEM()
        for bad in (b"", "str-seed", None, True, 123, b"x" * 1025):
            with self.assertRaises((TypeError, ValueError), msg=repr(bad)):
                kem.generate_keypair(bad)  # type: ignore[arg-type]

    def test_keypair_as_dict_pins(self):
        kp = PQCKEM().generate_keypair(b"seed")
        d = kp.as_dict()
        self.assertEqual(d["version"], "pqc-kem.v1")
        self.assertEqual(d["schema"], pqc_kem.SCHEMA_PIN)
        self.assertEqual(d["param_set"], "ml-kem-768")
        self.assertTrue(d["public_key_pin"].startswith("sha256:"))
        self.assertTrue(d["secret_key_pin"].startswith("sha256:"))

    def test_keypair_schema_pin_enforced(self):
        with self.assertRaises(PqcKemError):
            KeyPair(public_key=b"0" * 32, secret_key=b"1" * 32,
                    param_set="ml-kem-768", schema="wrong")


class TestEncapsDecaps(unittest.TestCase):
    def setUp(self):
        self.kem = PQCKEM()
        self.kp = self.kem.generate_keypair(b"test-seed")

    def test_roundtrip(self):
        enc = self.kem.encaps(self.kp.public_key, b"nonce-001")
        ss = self.kem.decaps(self.kp.secret_key, enc.ciphertext)
        self.assertEqual(ss, enc.shared_secret)
        self.assertEqual(len(ss), 32)

    def test_encaps_deterministic(self):
        a = self.kem.encaps(self.kp.public_key, b"n")
        b = self.kem.encaps(self.kp.public_key, b"n")
        self.assertEqual(a.ciphertext, b.ciphertext)
        self.assertEqual(a.shared_secret, b.shared_secret)

    def test_nonce_distinctness(self):
        a = self.kem.encaps(self.kp.public_key, b"n1")
        b = self.kem.encaps(self.kp.public_key, b"n2")
        self.assertNotEqual(a.ciphertext, b.ciphertext)
        self.assertNotEqual(a.shared_secret, b.shared_secret)

    def test_ciphertext_embeds_tag(self):
        enc = self.kem.encaps(self.kp.public_key, b"abc")
        self.assertEqual(len(enc.ciphertext), 3 + 32)

    def test_encaps_validation(self):
        with self.assertRaises((TypeError, ValueError)):
            self.kem.encaps(b"short", b"nonce")
        with self.assertRaises((TypeError, ValueError)):
            self.kem.encaps(self.kp.public_key, b"")
        with self.assertRaises((TypeError, ValueError)):
            self.kem.encaps(self.kp.public_key, "nonce")  # type: ignore[arg-type]
        with self.assertRaises((TypeError, ValueError)):
            self.kem.encaps(self.kp.public_key, True)  # type: ignore[arg-type]
        with self.assertRaises((TypeError, ValueError)):
            self.kem.encaps(self.kp.public_key, b"x" * 65)

    def test_wrong_secret_key_fails_closed(self):
        enc = self.kem.encaps(self.kp.public_key, b"nonce")
        other = self.kem.generate_keypair(b"other-seed")
        with self.assertRaises(DecapsulationError):
            self.kem.decaps(other.secret_key, enc.ciphertext)

    def test_tampered_ciphertext_fails_closed(self):
        enc = self.kem.encaps(self.kp.public_key, b"nonce")
        tampered = bytearray(enc.ciphertext)
        tampered[-1] ^= 0xFF
        with self.assertRaises(DecapsulationError):
            self.kem.decaps(self.kp.secret_key, bytes(tampered))

    def test_tampered_nonce_fails_closed(self):
        enc = self.kem.encaps(self.kp.public_key, b"nonce")
        tampered = b"Xonce" + enc.ciphertext[5:]
        with self.assertRaises(DecapsulationError):
            self.kem.decaps(self.kp.secret_key, tampered)

    def test_cross_recipient_ciphertext_refused(self):
        alice = self.kem.generate_keypair(b"alice")
        bob = self.kem.generate_keypair(b"bob")
        enc = self.kem.encaps(alice.public_key, b"nonce")
        with self.assertRaises(DecapsulationError):
            self.kem.decaps(bob.secret_key, enc.ciphertext)

    def test_decaps_validation(self):
        enc = self.kem.encaps(self.kp.public_key, b"nonce")
        with self.assertRaises((TypeError, ValueError)):
            self.kem.decaps(self.kp.secret_key, b"tiny")
        with self.assertRaises((TypeError, ValueError)):
            self.kem.decaps("not-bytes", enc.ciphertext)  # type: ignore[arg-type]

    def test_encapsulation_record(self):
        enc = self.kem.encaps(self.kp.public_key, b"nonce")
        d = enc.as_dict()
        self.assertEqual(d["version"], "pqc-kem.v1")
        self.assertTrue(d["ciphertext_pin"].startswith("sha256:"))
        self.assertTrue(d["shared_secret_pin"].startswith("sha256:"))

    def test_encapsulation_wrong_ss_length_rejected(self):
        with self.assertRaises(PqcKemError):
            Encapsulation(ciphertext=b"c" * 35, shared_secret=b"s" * 31,
                          param_set="ml-kem-768")


class TestAuditEvents(unittest.TestCase):
    def test_shapes(self):
        for kind in ("keygen", "encapsulated", "decapsulated", "decaps-rejected"):
            ev = pqc_kem_audit_event(kind, 7, note="x")
            self.assertEqual(ev["event"], "pqc-kem")
            self.assertEqual(ev["kind"], kind)
            self.assertEqual(ev["audit_seq"], 7)
            self.assertEqual(ev["schema"], "audit.ndjson/1")
            self.assertEqual(ev["note"], "x")

    def test_bad_kind_rejected(self):
        with self.assertRaises(ValueError):
            pqc_kem_audit_event("exploded", 1)

    def test_bad_seq_rejected(self):
        for bad in (-1, True, "1", 1.5, None):
            with self.assertRaises(ValueError, msg=repr(bad)):
                pqc_kem_audit_event("keygen", bad)  # type: ignore[arg-type]


class TestMain(unittest.TestCase):
    def test_main_runs(self):
        pqc_kem.main()  # asserts internally


if __name__ == "__main__":
    unittest.main()
