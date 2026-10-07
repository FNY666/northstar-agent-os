"""Tests for pqc_sig (post-quantum signature interface, simulated)."""

import unittest

import pqc_sig
from pqc_sig import (
    AUDIT_FORMAT,
    DILITHIUM,
    FALCON,
    PQC_SIG_VERSION,
    SCHEMA_PIN,
    SPHINCS,
    SUPPORTED_SCHEMES,
    PQCSig,
    PQCSigError,
    KeyPair,
    MigrationRecord,
    PublicKey,
    SecretKey,
    Signature,
    migrate,
    pqc_sig_audit_event,
    scheme_info,
)


class TestPins(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(PQC_SIG_VERSION, "pqc-sig.v1")

    def test_schema_pin(self):
        self.assertEqual(SCHEMA_PIN, "northstar.pqc-sig.v1")

    def test_supported_schemes(self):
        self.assertEqual(SUPPORTED_SCHEMES, {"dilithium", "falcon", "sphincs"})

    def test_unknown_scheme_constructor(self):
        with self.assertRaises(PQCSigError):
            PQCSig("rsa")

    def test_bool_scheme_rejected(self):
        with self.assertRaises(TypeError):
            PQCSig(True)


class TestSchemeInfo(unittest.TestCase):
    def test_dilithium_info(self):
        info = scheme_info(DILITHIUM)
        self.assertEqual(info.family, "module-lattice")
        self.assertEqual(info.standard, "FIPS 204")
        self.assertEqual(info.security_level, 2)
        self.assertGreater(info.public_key_bytes, 0)
        self.assertGreater(info.secret_key_bytes, 0)
        self.assertGreater(info.signature_bytes, 0)

    def test_falcon_info(self):
        info = scheme_info(FALCON)
        self.assertEqual(info.family, "ntru-lattice")

    def test_sphincs_info(self):
        info = scheme_info(SPHINCS)
        self.assertEqual(info.family, "stateless-hash")
        self.assertEqual(info.standard, "FIPS 205")

    def test_info_determinism(self):
        self.assertEqual(
            scheme_info(DILITHIUM).params_digest,
            scheme_info(DILITHIUM).params_digest,
        )

    def test_info_unknown_scheme(self):
        with self.assertRaises(PQCSigError):
            scheme_info("ecdsa")

    def test_info_as_dict(self):
        d = scheme_info(DILITHIUM).as_dict()
        self.assertEqual(d["schema"], SCHEMA_PIN)
        self.assertEqual(d["version"], PQC_SIG_VERSION)
        self.assertEqual(d["scheme"], DILITHIUM)


class TestKeygen(unittest.TestCase):
    def test_deterministic(self):
        a = PQCSig(DILITHIUM).keygen(b"seed")
        b = PQCSig(DILITHIUM).keygen(b"seed")
        self.assertEqual(a.public_key.key_id, b.public_key.key_id)
        self.assertEqual(a.public_key.public_pin, b.public_key.public_pin)

    def test_distinct_seeds(self):
        a = PQCSig(DILITHIUM).keygen(b"one")
        b = PQCSig(DILITHIUM).keygen(b"two")
        self.assertNotEqual(a.public_key.key_id, b.public_key.key_id)

    def test_empty_seed_allowed(self):
        keys = PQCSig(FALCON).keygen()
        self.assertTrue(keys.public_key.key_id.startswith("sha256:"))

    def test_bad_seed_type(self):
        with self.assertRaises(TypeError):
            PQCSig(DILITHIUM).keygen("not-bytes")

    def test_bool_seed_rejected(self):
        with self.assertRaises(TypeError):
            PQCSig(DILITHIUM).keygen(True)

    def test_keypair_shape(self):
        keys = PQCSig(SPHINCS).keygen(b"x")
        self.assertIsInstance(keys, KeyPair)
        self.assertIsInstance(keys.public_key, PublicKey)
        self.assertIsInstance(keys.secret_key, SecretKey)
        self.assertEqual(keys.public_key.scheme, SPHINCS)
        self.assertEqual(
            keys.public_key.key_id, keys.secret_key.key_id
        )

    def test_session_scheme_property(self):
        self.assertEqual(PQCSig(FALCON).scheme, FALCON)
        self.assertEqual(PQCSig(FALCON).params.scheme, FALCON)


class TestSignVerify(unittest.TestCase):
    def _roundtrip(self, scheme):
        session = PQCSig(scheme)
        keys = session.keygen(b"rt")
        sig = session.sign(keys.secret_key, "hello", 1)
        self.assertTrue(session.verify(keys.public_key, "hello", sig))
        return session, keys, sig

    def test_roundtrip_all_schemes(self):
        for scheme in (DILITHIUM, FALCON, SPHINCS):
            self._roundtrip(scheme)

    def test_wrong_message_fails(self):
        session, keys, sig = self._roundtrip(DILITHIUM)
        self.assertFalse(session.verify(keys.public_key, "other", sig))

    def test_tampered_sig_fails(self):
        session, keys, sig = self._roundtrip(FALCON)
        bad_hex = "00" + sig.sig_hex[2:]
        from dataclasses import replace

        bad = replace(sig, sig_hex=bad_hex)
        self.assertFalse(session.verify(keys.public_key, "hello", bad))

    def test_wrong_key_fails(self):
        session = PQCSig(DILITHIUM)
        keys = session.keygen(b"a")
        other = session.keygen(b"b")
        sig = session.sign(keys.secret_key, "hello", 1)
        self.assertFalse(session.verify(other.public_key, "hello", sig))

    def test_cross_scheme_never_verifies(self):
        d = PQCSig(DILITHIUM)
        f = PQCSig(FALCON)
        dkeys = d.keygen(b"k")
        fkeys = f.keygen(b"k")
        sig = d.sign(dkeys.secret_key, "hello", 1)
        self.assertFalse(f.verify(fkeys.public_key, "hello", sig))
        self.assertFalse(d.verify(fkeys.public_key, "hello", sig))

    def test_sign_wrong_scheme_key_refused(self):
        d = PQCSig(DILITHIUM)
        fkeys = PQCSig(FALCON).keygen(b"k")
        with self.assertRaises(PQCSigError):
            d.sign(fkeys.secret_key, "hello", 1)

    def test_type_tagged_messages(self):
        session = PQCSig(SPHINCS)
        keys = session.keygen(b"t")
        sig_str = session.sign(keys.secret_key, "m", 1)
        sig_bytes = session.sign(keys.secret_key, b"m", 2)
        self.assertNotEqual(sig_str.sig_hex, sig_bytes.sig_hex)
        self.assertTrue(session.verify(keys.public_key, "m", sig_str))
        self.assertTrue(session.verify(keys.public_key, b"m", sig_bytes))
        self.assertFalse(session.verify(keys.public_key, b"m", sig_str))

    def test_bad_message_type(self):
        session = PQCSig(DILITHIUM)
        keys = session.keygen(b"t")
        with self.assertRaises(TypeError):
            session.sign(keys.secret_key, 123, 1)
        with self.assertRaises(TypeError):
            session.sign(keys.secret_key, None, 1)

    def test_bool_seq_rejected(self):
        session = PQCSig(DILITHIUM)
        keys = session.keygen(b"t")
        with self.assertRaises(TypeError):
            session.sign(keys.secret_key, "m", True)

    def test_negative_seq_rejected(self):
        session = PQCSig(DILITHIUM)
        keys = session.keygen(b"t")
        with self.assertRaises(ValueError):
            session.sign(keys.secret_key, "m", -1)

    def test_sign_with_public_key_refused(self):
        session = PQCSig(DILITHIUM)
        keys = session.keygen(b"t")
        with self.assertRaises(TypeError):
            session.sign(keys.public_key, "m", 1)

    def test_verify_bad_types_raise(self):
        session = PQCSig(DILITHIUM)
        keys = session.keygen(b"t")
        sig = session.sign(keys.secret_key, "m", 1)
        with self.assertRaises(TypeError):
            session.verify("nope", "m", sig)
        with self.assertRaises(TypeError):
            session.verify(keys.public_key, "m", "nope")

    def test_signature_message_digest_bound(self):
        session = PQCSig(DILITHIUM)
        keys = session.keygen(b"t")
        sig = session.sign(keys.secret_key, "m", 1)
        self.assertTrue(sig.message_digest.startswith("sha256:"))

    def test_empty_message_ok(self):
        session = PQCSig(FALCON)
        keys = session.keygen(b"t")
        sig = session.sign(keys.secret_key, b"", 1)
        self.assertTrue(session.verify(keys.public_key, b"", sig))


class TestFrozen(unittest.TestCase):
    def test_signature_frozen(self):
        session = PQCSig(DILITHIUM)
        keys = session.keygen(b"t")
        sig = session.sign(keys.secret_key, "m", 1)
        with self.assertRaises(Exception):
            sig.seq = 2

    def test_signature_as_dict(self):
        session = PQCSig(DILITHIUM)
        keys = session.keygen(b"t")
        sig = session.sign(keys.secret_key, "m", 1)
        d = sig.as_dict()
        self.assertEqual(d["schema"], SCHEMA_PIN)
        self.assertEqual(d["version"], PQC_SIG_VERSION)
        self.assertEqual(d["seq"], 1)

    def test_public_key_as_dict(self):
        keys = PQCSig(DILITHIUM).keygen(b"t")
        d = keys.public_key.as_dict()
        self.assertEqual(d["schema"], SCHEMA_PIN)

    def test_secret_as_dict_hides_raw(self):
        keys = PQCSig(DILITHIUM).keygen(b"t")
        d = keys.secret_key.as_dict()
        self.assertNotIn("secret_hex", d)
        self.assertIn("secret_pin", d)


class TestMigrate(unittest.TestCase):
    def test_migrate_shape(self):
        old = PQCSig(DILITHIUM).keygen(b"old")
        new_keys, record = migrate(old.public_key, FALCON, b"new", seq=3)
        self.assertIsInstance(record, MigrationRecord)
        self.assertEqual(record.old_scheme, DILITHIUM)
        self.assertEqual(record.new_scheme, FALCON)
        self.assertEqual(record.old_key_id, old.public_key.key_id)
        self.assertEqual(record.new_key_id, new_keys.public_key.key_id)
        self.assertEqual(record.seq, 3)
        self.assertEqual(new_keys.public_key.scheme, FALCON)

    def test_migrate_new_key_usable(self):
        old = PQCSig(SPHINCS).keygen(b"old")
        new_keys, _ = migrate(old.public_key, DILITHIUM, b"new")
        session = PQCSig(DILITHIUM)
        sig = session.sign(new_keys.secret_key, "after", 1)
        self.assertTrue(session.verify(new_keys.public_key, "after", sig))

    def test_migrate_same_scheme_refused(self):
        old = PQCSig(DILITHIUM).keygen(b"old")
        with self.assertRaises(PQCSigError):
            migrate(old.public_key, DILITHIUM, b"x")

    def test_migrate_bad_scheme(self):
        old = PQCSig(DILITHIUM).keygen(b"old")
        with self.assertRaises(PQCSigError):
            migrate(old.public_key, "rsa", b"x")

    def test_migrate_record_as_dict(self):
        old = PQCSig(DILITHIUM).keygen(b"old")
        _, record = migrate(old.public_key, FALCON, b"x", seq=1)
        d = record.as_dict()
        self.assertEqual(d["schema"], SCHEMA_PIN)


class TestAudit(unittest.TestCase):
    def test_event_shape(self):
        ev = pqc_sig_audit_event("signed", 2, scheme=DILITHIUM,
                                 key_id="sha256:abc",
                                 message_digest="sha256:def")
        self.assertEqual(ev["format"], AUDIT_FORMAT)
        self.assertEqual(ev["module"], PQC_SIG_VERSION)
        self.assertEqual(ev["schema"], SCHEMA_PIN)
        self.assertEqual(ev["kind"], "pqc-sig-signed")
        self.assertEqual(ev["seq"], 2)
        self.assertEqual(ev["scheme"], DILITHIUM)

    def test_all_kinds(self):
        for kind in ("keygen", "signed", "verified", "rejected",
                     "migrated"):
            ev = pqc_sig_audit_event(kind, 0)
            self.assertEqual(ev["kind"], f"pqc-sig-{kind}")

    def test_bad_kind(self):
        with self.assertRaises(ValueError):
            pqc_sig_audit_event("forged", 0)

    def test_bad_seq(self):
        with self.assertRaises(TypeError):
            pqc_sig_audit_event("signed", True)
        with self.assertRaises(ValueError):
            pqc_sig_audit_event("signed", -1)

    def test_secret_never_in_audit(self):
        ev = pqc_sig_audit_event("keygen", 1, key_id="sha256:abc")
        blob = str(ev)
        self.assertNotIn("secret", blob)


class TestMain(unittest.TestCase):
    def test_main(self):
        pqc_sig.main()


if __name__ == "__main__":
    unittest.main()
