"""Tests for timelock_enc: seal to a future seq, refuse early opens."""

import unittest

from timelock_enc import (
    TIMELOCK_ENC_SCHEMA,
    TIMELOCK_ENC_VERSION,
    DEFAULT_MAX_PUZZLE_STEPS,
    IntegrityError,
    TimelockCiphertext,
    TimelockEnc,
    TimelockEncError,
    TooEarlyError,
    timelock_enc_audit_event,
)


class TestPins(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(TIMELOCK_ENC_VERSION, "timelock-enc.v1")

    def test_schema_pin(self):
        self.assertEqual(TIMELOCK_ENC_SCHEMA, "northstar.timelock-enc.v1")

    def test_max_steps_default(self):
        self.assertEqual(TimelockEnc().max_puzzle_steps, DEFAULT_MAX_PUZZLE_STEPS)


class TestConstructor(unittest.TestCase):
    def test_bad_max_steps_type(self):
        with self.assertRaises(TypeError):
            TimelockEnc(max_puzzle_steps="100")

    def test_bool_max_steps(self):
        with self.assertRaises(TypeError):
            TimelockEnc(max_puzzle_steps=True)

    def test_nonpositive_max_steps(self):
        with self.assertRaises(ValueError):
            TimelockEnc(max_puzzle_steps=0)
        with self.assertRaises(ValueError):
            TimelockEnc(max_puzzle_steps=-5)


class TestEncrypt(unittest.TestCase):
    def setUp(self):
        self.engine = TimelockEnc()

    def test_happy_path(self):
        rec = self.engine.encrypt(b"secret", 10)
        self.assertIsInstance(rec, TimelockCiphertext)
        self.assertEqual(rec.unlock_seq, 10)
        self.assertTrue(rec.digest().startswith("sha256:"))

    def test_data_must_be_bytes(self):
        with self.assertRaises(TypeError):
            self.engine.encrypt("secret", 10)
        with self.assertRaises(TypeError):
            self.engine.encrypt(None, 10)
        with self.assertRaises(TypeError):
            self.engine.encrypt(123, 10)

    def test_unlock_seq_validation(self):
        with self.assertRaises(TypeError):
            self.engine.encrypt(b"x", True)
        with self.assertRaises(TypeError):
            self.engine.encrypt(b"x", 1.5)
        with self.assertRaises(ValueError):
            self.engine.encrypt(b"x", -1)

    def test_unlock_seq_over_max(self):
        engine = TimelockEnc(max_puzzle_steps=100)
        with self.assertRaises(ValueError):
            engine.encrypt(b"x", 101)

    def test_deterministic(self):
        a = self.engine.encrypt(b"same", 7)
        b = self.engine.encrypt(b"same", 7)
        self.assertEqual(a.to_bytes(), b.to_bytes())

    def test_unlock_seq_changes_ciphertext(self):
        a = self.engine.encrypt(b"same", 7)
        b = self.engine.encrypt(b"same", 8)
        self.assertNotEqual(a.to_bytes(), b.to_bytes())

    def test_empty_data(self):
        rec = self.engine.encrypt(b"", 3)
        self.assertEqual(self.engine.decrypt(rec, 3), b"")


class TestDecrypt(unittest.TestCase):
    def setUp(self):
        self.engine = TimelockEnc()
        self.rec = self.engine.encrypt(b"future payload", 50)

    def test_happy_path_at_unlock(self):
        self.assertEqual(self.engine.decrypt(self.rec, 50), b"future payload")

    def test_happy_path_after_unlock(self):
        self.assertEqual(self.engine.decrypt(self.rec, 500), b"future payload")

    def test_too_early(self):
        with self.assertRaises(TooEarlyError) as ctx:
            self.engine.decrypt(self.rec, 49)
        self.assertEqual(ctx.exception.unlock_seq, 50)
        self.assertEqual(ctx.exception.current_seq, 49)

    def test_too_early_is_timelock_error(self):
        with self.assertRaises(TimelockEncError):
            self.engine.decrypt(self.rec, 0)

    def test_zero_unlock_seq_immediate(self):
        rec = self.engine.encrypt(b"now", 0)
        self.assertEqual(self.engine.decrypt(rec, 0), b"now")

    def test_record_type(self):
        with self.assertRaises(TypeError):
            self.engine.decrypt(b"not-a-record", 50)

    def test_current_seq_validation(self):
        with self.assertRaises(TypeError):
            self.engine.decrypt(self.rec, True)
        with self.assertRaises(TypeError):
            self.engine.decrypt(self.rec, "50")
        with self.assertRaises(ValueError):
            self.engine.decrypt(self.rec, -1)

    def test_tampered_ciphertext_rejected(self):
        tampered = bytearray(self.rec.ciphertext)
        tampered[0] ^= 0xFF
        bad = TimelockCiphertext(
            ciphertext=bytes(tampered),
            unlock_seq=self.rec.unlock_seq,
            seed=self.rec.seed,
            tag=self.rec.tag,
        )
        with self.assertRaises(IntegrityError):
            self.engine.decrypt(bad, 50)

    def test_transplanted_seed_rejected(self):
        other = self.engine.encrypt(b"other", 50)
        bad = TimelockCiphertext(
            ciphertext=self.rec.ciphertext,
            unlock_seq=self.rec.unlock_seq,
            seed=other.seed,
            tag=self.rec.tag,
        )
        with self.assertRaises(IntegrityError):
            self.engine.decrypt(bad, 50)

    def test_multiblock_payload(self):
        big = bytes(range(256)) * 10  # 2560 bytes, spans blocks
        rec = self.engine.encrypt(big, 20)
        self.assertEqual(self.engine.decrypt(rec, 20), big)


class TestRecord(unittest.TestCase):
    def test_frozen(self):
        rec = TimelockEnc().encrypt(b"x", 1)
        with self.assertRaises(Exception):
            rec.unlock_seq = 99  # type: ignore

    def test_validation_branches(self):
        with self.assertRaises(TypeError):
            TimelockCiphertext(ciphertext="x", unlock_seq=1,
                               seed=b"\x00" * 32, tag=b"\x00" * 32)
        with self.assertRaises(TypeError):
            TimelockCiphertext(ciphertext=b"x", unlock_seq=True,
                               seed=b"\x00" * 32, tag=b"\x00" * 32)
        with self.assertRaises(ValueError):
            TimelockCiphertext(ciphertext=b"x", unlock_seq=-1,
                               seed=b"\x00" * 32, tag=b"\x00" * 32)
        with self.assertRaises(ValueError):
            TimelockCiphertext(ciphertext=b"x", unlock_seq=1,
                               seed=b"\x00" * 31, tag=b"\x00" * 32)
        with self.assertRaises(ValueError):
            TimelockCiphertext(ciphertext=b"x", unlock_seq=1,
                               seed=b"\x00" * 32, tag=b"\x00" * 31)

    def test_digest_deterministic(self):
        e = TimelockEnc()
        self.assertEqual(e.encrypt(b"x", 2).digest(), e.encrypt(b"x", 2).digest())

    def test_as_dict_shape(self):
        d = TimelockEnc().encrypt(b"x", 2).as_dict()
        self.assertEqual(d["schema"], TIMELOCK_ENC_SCHEMA)
        self.assertEqual(d["version"], TIMELOCK_ENC_VERSION)
        self.assertEqual(d["unlock_seq"], 2)
        self.assertIn("digest", d)

    def test_wire_roundtrip(self):
        rec = TimelockEnc().encrypt(b"wire me", 9)
        back = TimelockCiphertext.from_bytes(rec.to_bytes())
        self.assertEqual(back.digest(), rec.digest())
        self.assertEqual(TimelockEnc().decrypt(back, 9), b"wire me")

    def test_wire_tamper(self):
        rec = TimelockEnc().encrypt(b"wire me", 9)
        raw = bytearray(rec.to_bytes())
        raw[20] ^= 0x01
        with self.assertRaises(IntegrityError):
            TimelockCiphertext.from_bytes(bytes(raw))

    def test_wire_bad_magic(self):
        rec = TimelockEnc().encrypt(b"wire me", 9)
        raw = bytearray(rec.to_bytes())
        raw[0:4] = b"XXXX"
        # recompute pin so the pin check passes and magic is reached
        import hashlib
        body = bytes(raw[:-32])
        raw[-32:] = hashlib.sha256(body).digest()
        with self.assertRaises(TimelockEncError):
            TimelockCiphertext.from_bytes(bytes(raw))

    def test_wire_type_rejection(self):
        with self.assertRaises(TypeError):
            TimelockCiphertext.from_bytes("not-bytes")
        with self.assertRaises(TimelockEncError):
            TimelockCiphertext.from_bytes(b"\x00" * 10)


class TestAuditEvent(unittest.TestCase):
    def test_shapes(self):
        for kind in ("encrypted", "decrypted", "decrypt-refused", "integrity-failed"):
            ev = timelock_enc_audit_event(kind, unlock_seq=5, seq=1)
            self.assertEqual(ev["schema"], "audit.ndjson/1")
            self.assertEqual(ev["kind"], f"timelock-enc.{kind}")
            self.assertEqual(ev["module"], TIMELOCK_ENC_SCHEMA)
            self.assertEqual(ev["version"], TIMELOCK_ENC_VERSION)
            self.assertEqual(ev["unlock_seq"], 5)
            self.assertEqual(ev["seq"], 1)

    def test_bad_kind(self):
        with self.assertRaises(ValueError):
            timelock_enc_audit_event("nope", unlock_seq=5, seq=1)

    def test_bad_seqs(self):
        with self.assertRaises(TypeError):
            timelock_enc_audit_event("encrypted", unlock_seq=True, seq=1)
        with self.assertRaises(ValueError):
            timelock_enc_audit_event("encrypted", unlock_seq=-1, seq=1)
        with self.assertRaises(ValueError):
            timelock_enc_audit_event("encrypted", unlock_seq=5, seq=-1)
        with self.assertRaises(ValueError):
            timelock_enc_audit_event("encrypted", unlock_seq=5, seq=True)


class TestMain(unittest.TestCase):
    def test_main(self):
        from timelock_enc import main
        main()  # must not raise


if __name__ == "__main__":
    unittest.main()
