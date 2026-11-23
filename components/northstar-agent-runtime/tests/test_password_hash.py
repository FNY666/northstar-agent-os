"""Tests for password_hash (Argon2id/scrypt/bcrypt shapes, simulated)."""

import unittest

from password_hash import (
    PasswordHashError,
    PasswordHashRecord,
    PasswordHasher,
    PASSWORD_HASH_VERSION,
    PASSWORD_HASH_SCHEMA,
    SCHEME_ARGON2ID,
    SCHEME_SCRYPT,
    SCHEME_BCRYPT,
    parse,
    password_hash_audit_event,
)


def _hasher(**kwargs):
    kwargs.setdefault("memory_cost_kib", 1024)
    return PasswordHasher(**kwargs)


class TestConstruction(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(PASSWORD_HASH_VERSION, "password-hash.v1")
        self.assertEqual(PASSWORD_HASH_SCHEMA, "northstar.password-hash.v1")

    def test_scheme_vocabulary(self):
        for scheme in (SCHEME_ARGON2ID, SCHEME_SCRYPT, SCHEME_BCRYPT):
            self.assertEqual(_hasher(scheme=scheme).scheme, scheme)

    def test_unknown_scheme_rejected(self):
        with self.assertRaises(PasswordHashError):
            PasswordHasher(scheme="rot13")

    def test_time_cost_bounds(self):
        _hasher(time_cost=1)
        _hasher(time_cost=100)
        with self.assertRaises(PasswordHashError):
            _hasher(time_cost=0)
        with self.assertRaises(PasswordHashError):
            _hasher(time_cost=101)

    def test_bool_time_cost_rejected(self):
        with self.assertRaises(TypeError):
            _hasher(time_cost=True)

    def test_parallelism_bounds(self):
        with self.assertRaises(PasswordHashError):
            _hasher(parallelism=0)
        with self.assertRaises(PasswordHashError):
            _hasher(parallelism=17)


class TestHash(unittest.TestCase):
    def test_hash_record_shape(self):
        rec = _hasher().hash_password("s3cret!", seq=1)
        self.assertEqual(rec.version, "password-hash.v1")
        self.assertEqual(rec.scheme, "argon2id")
        self.assertEqual(rec.time_cost, 3)
        self.assertEqual(len(rec.salt), 32)
        self.assertEqual(len(rec.digest), 64)
        self.assertTrue(rec.encoded.startswith("$password-hash$v=1$argon2id$"))

    def test_salts_unique_per_hash(self):
        h = _hasher()
        r1 = h.hash_password("same", seq=1)
        r2 = h.hash_password("same", seq=2)
        self.assertNotEqual(r1.salt, r2.salt)
        self.assertNotEqual(r1.digest, r2.digest)

    def test_params_pinned_in_digest(self):
        h1 = _hasher(time_cost=2, parallelism=1)
        h2 = _hasher(time_cost=2, parallelism=2)
        r1 = h1.hash_password("pw", seq=1)
        r2 = h2.hash_password("pw", seq=2)
        self.assertNotEqual(r1.digest, r2.digest)

    def test_scheme_pinned_in_digest(self):
        h1 = _hasher(scheme=SCHEME_ARGON2ID)
        h2 = _hasher(scheme=SCHEME_SCRYPT)
        r1 = h1.hash_password("pw", seq=1)
        r2 = h2.hash_password("pw", seq=2)
        self.assertNotEqual(r1.digest, r2.digest)

    def test_empty_password_refused(self):
        with self.assertRaises(PasswordHashError):
            _hasher().hash_password("", seq=1)

    def test_bool_password_rejected(self):
        with self.assertRaises(TypeError):
            _hasher().hash_password(True, seq=1)

    def test_non_str_password_rejected(self):
        with self.assertRaises(TypeError):
            _hasher().hash_password(None, seq=1)
        with self.assertRaises(TypeError):
            _hasher().hash_password(b"bytes", seq=1)

    def test_oversize_password_refused(self):
        with self.assertRaises(PasswordHashError):
            _hasher().hash_password("x" * 5000, seq=1)

    def test_bad_seq_rejected(self):
        with self.assertRaises(ValueError):
            _hasher().hash_password("pw", seq=-1)
        with self.assertRaises(TypeError):
            _hasher().hash_password("pw", seq=True)

    def test_record_frozen(self):
        rec = _hasher().hash_password("pw", seq=1)
        with self.assertRaises(Exception):
            rec.digest = "00" * 32  # type: ignore[misc]

    def test_as_dict_schema_pin(self):
        rec = _hasher().hash_password("pw", seq=1)
        d = rec.as_dict()
        self.assertEqual(d["schema"], PASSWORD_HASH_SCHEMA)
        self.assertEqual(d["scheme"], "argon2id")
        self.assertNotIn("pw", str(d))


class TestVerify(unittest.TestCase):
    def test_round_trip(self):
        h = _hasher()
        rec = h.hash_password("correct", seq=1)
        self.assertTrue(h.verify("correct", rec))

    def test_wrong_password_returns_false(self):
        h = _hasher()
        rec = h.hash_password("correct", seq=1)
        self.assertFalse(h.verify("incorrect", rec))

    def test_cross_hasher_verify(self):
        # Records are self-describing: any hasher can verify any record.
        h1 = _hasher(time_cost=2)
        h2 = _hasher(time_cost=3)
        rec = h1.hash_password("pw", seq=1)
        self.assertTrue(h2.verify("pw", rec))
        self.assertFalse(h2.verify("wrong", rec))

    def test_tampered_digest_fails(self):
        h = _hasher()
        rec = h.hash_password("pw", seq=1)
        tampered = PasswordHashRecord(
            version=rec.version, scheme=rec.scheme,
            time_cost=rec.time_cost, memory_cost_kib=rec.memory_cost_kib,
            parallelism=rec.parallelism, salt=rec.salt,
            digest="00" * 32, encoded=rec.encoded,
        )
        self.assertFalse(h.verify("pw", tampered))

    def test_bad_record_type_raises(self):
        h = _hasher()
        with self.assertRaises(TypeError):
            h.verify("pw", "not-a-record")


class TestParse(unittest.TestCase):
    def test_mcf_round_trip(self):
        h = _hasher(scheme=SCHEME_BCRYPT, time_cost=2, parallelism=2)
        rec = h.hash_password("pw", seq=1)
        back = parse(rec.encoded)
        self.assertEqual(back.digest, rec.digest)
        self.assertEqual(back.salt, rec.salt)
        self.assertEqual(back.scheme, SCHEME_BCRYPT)
        self.assertTrue(h.verify("pw", back))

    def test_parse_rejects_garbage(self):
        for bad in ("", "not-mcf", "$argon2$v=1$x$y", "$password-hash$v=1$x$m=1,t=1,p=1$s$d"):
            with self.assertRaises((PasswordHashError, TypeError), msg=bad):
                parse(bad)

    def test_parse_rejects_bad_params(self):
        h = _hasher()
        rec = h.hash_password("pw", seq=1)
        mangled = rec.encoded.replace("t=3", "t=0")
        with self.assertRaises(PasswordHashError):
            parse(mangled)

    def test_parse_rejects_wrong_encoding_version(self):
        h = _hasher()
        rec = h.hash_password("pw", seq=1)
        with self.assertRaises(PasswordHashError):
            parse(rec.encoded.replace("$v=1$", "$v=2$"))


class TestNeedsRehash(unittest.TestCase):
    def test_same_policy_no_rehash(self):
        h = _hasher()
        rec = h.hash_password("pw", seq=1)
        self.assertFalse(h.needs_rehash(rec))

    def test_changed_time_cost_needs_rehash(self):
        rec = _hasher(time_cost=2).hash_password("pw", seq=1)
        self.assertTrue(_hasher(time_cost=3).needs_rehash(rec))

    def test_changed_scheme_needs_rehash(self):
        rec = _hasher(scheme=SCHEME_SCRYPT).hash_password("pw", seq=1)
        self.assertTrue(_hasher(scheme=SCHEME_ARGON2ID).needs_rehash(rec))


class TestAudit(unittest.TestCase):
    def test_event_shapes(self):
        h = _hasher()
        rec = h.hash_password("pw", seq=1)
        for kind in ("hashed", "verified", "verification-failed", "parse-rejected"):
            ev = password_hash_audit_event(kind, rec, seq=7)
            self.assertEqual(ev["schema"], "audit.ndjson/1")
            self.assertEqual(ev["kind"], kind)
            self.assertEqual(ev["event"], "password-hash")
            self.assertEqual(ev["digest"], rec.digest)
            self.assertNotIn("pw", str(ev))

    def test_event_rejects_bad_kind(self):
        rec = _hasher().hash_password("pw", seq=1)
        with self.assertRaises(ValueError):
            password_hash_audit_event("leaked", rec, seq=1)


class TestMain(unittest.TestCase):
    def test_main_self_check(self):
        from password_hash import main
        main()


if __name__ == "__main__":
    unittest.main()
