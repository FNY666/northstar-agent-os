"""Tests for fhe_interface.py."""

import sys
import unittest

sys.path.insert(0, "..")

from fhe_interface import (
    ADD_NOISE,
    MAX_NOISE,
    MUL_NOISE,
    PLAINTEXT_BOUND,
    Ciphertext,
    EvalOp,
    FHE,
    FHEError,
    FHE_INTERFACE_SCHEMA,
    FHE_INTERFACE_VERSION,
    IntegrityError,
    KeyMismatchError,
    KeyPair,
    NoiseExceededError,
    EvalReport,
    fhe_audit_event,
    keygen,
    main as fhe_main,
)

SEED_A = b"test-seed-a-0123456789abcdef01234567"
SEED_B = b"test-seed-b-0123456789abcdef01234567"


class TestPins(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(FHE_INTERFACE_VERSION, "fhe-interface.v1")
        self.assertEqual(FHE_INTERFACE_SCHEMA, "northstar.fhe-interface.v1")

    def test_keypair_as_dict(self):
        kp = keygen(SEED_A)
        d = kp.as_dict()
        self.assertEqual(d["schema"], FHE_INTERFACE_SCHEMA)
        self.assertTrue(d["key_id"].startswith("fhe:"))

    def test_ciphertext_as_dict(self):
        fhe = FHE(SEED_A)
        ct = fhe.encrypt(5, 0)
        d = ct.as_dict()
        self.assertEqual(d["schema"], FHE_INTERFACE_SCHEMA)
        self.assertEqual(d["version"], FHE_INTERFACE_VERSION)
        self.assertEqual(d["value"], 5)
        self.assertEqual(d["noise"], 0)


class TestKeygen(unittest.TestCase):
    def test_deterministic(self):
        self.assertEqual(keygen(SEED_A), keygen(SEED_A))

    def test_distinct_seeds(self):
        self.assertNotEqual(keygen(SEED_A).key_id, keygen(SEED_B).key_id)

    def test_pins_sha256(self):
        kp = keygen(SEED_A)
        self.assertTrue(kp.public_pin.startswith("sha256:"))
        self.assertTrue(kp.secret_pin.startswith("sha256:"))

    def test_bad_seed_types(self):
        for bad in (b"", "str", None, 42, bytearray(b"x")):
            with self.assertRaises(TypeError):
                keygen(bad)

    def test_oversize_seed(self):
        with self.assertRaises(ValueError):
            keygen(b"x" * 1025)


class TestEncryptDecrypt(unittest.TestCase):
    def setUp(self):
        self.fhe = FHE(SEED_A)

    def test_roundtrip(self):
        for v in (0, 1, -1, 42, -999, 2**62):
            self.assertEqual(self.fhe.decrypt(self.fhe.encrypt(v, 0)), v)

    def test_fresh_noise_zero(self):
        self.assertEqual(self.fhe.encrypt(3, 0).noise, 0)

    def test_bool_rejected(self):
        with self.assertRaises(TypeError):
            self.fhe.encrypt(True, 0)

    def test_non_int_rejected(self):
        for bad in ("5", 5.0, None, [5]):
            with self.assertRaises(TypeError):
                self.fhe.encrypt(bad, 0)

    def test_bound_rejected(self):
        with self.assertRaises(FHEError):
            self.fhe.encrypt(PLAINTEXT_BOUND, 0)
        with self.assertRaises(FHEError):
            self.fhe.encrypt(-PLAINTEXT_BOUND, 0)

    def test_negative_seq_rejected(self):
        with self.assertRaises(ValueError):
            self.fhe.encrypt(1, -1)
        with self.assertRaises(ValueError):
            self.fhe.encrypt(1, True)

    def test_keypair_property(self):
        self.assertIsInstance(self.fhe.keypair, KeyPair)


class TestHomomorphicOps(unittest.TestCase):
    def setUp(self):
        self.fhe = FHE(SEED_A)

    def test_add(self):
        c = self.fhe.add(self.fhe.encrypt(7, 0), self.fhe.encrypt(6, 1), 2)
        self.assertEqual(self.fhe.decrypt(c), 13)
        self.assertEqual(c.noise, 0 + 0 + ADD_NOISE)

    def test_multiply(self):
        c = self.fhe.multiply(self.fhe.encrypt(7, 0), self.fhe.encrypt(6, 1), 2)
        self.assertEqual(self.fhe.decrypt(c), 42)

    def test_add_noise_compounds(self):
        c = self.fhe.add(self.fhe.encrypt(1, 0), self.fhe.encrypt(1, 1), 2)
        c2 = self.fhe.add(c, self.fhe.encrypt(1, 3), 4)
        self.assertEqual(c2.noise, ADD_NOISE + 0 + ADD_NOISE)
        self.assertEqual(self.fhe.decrypt(c2), 3)

    def test_negative_values(self):
        c = self.fhe.add(self.fhe.encrypt(-5, 0), self.fhe.encrypt(3, 1), 2)
        self.assertEqual(self.fhe.decrypt(c), -2)
        m = self.fhe.multiply(self.fhe.encrypt(-5, 0), self.fhe.encrypt(3, 1), 3)
        self.assertEqual(self.fhe.decrypt(m), -15)

    def test_mul_overflow_fail_closed(self):
        big = self.fhe.encrypt(2**62, 0)
        with self.assertRaises(FHEError):
            self.fhe.multiply(big, big, 1)

    def test_key_mismatch(self):
        other = FHE(SEED_B)
        c1 = self.fhe.encrypt(1, 0)
        c2 = other.encrypt(2, 0)
        with self.assertRaises(KeyMismatchError):
            self.fhe.add(c1, c2, 1)
        with self.assertRaises(KeyMismatchError):
            self.fhe.multiply(c1, c2, 1)

    def test_tampered_ciphertext(self):
        ct = self.fhe.encrypt(9, 0)
        evil = Ciphertext(ct.key_id, ct.value + 1, ct.noise, ct.nonce, ct.digest)
        with self.assertRaises(IntegrityError):
            self.fhe.decrypt(evil)

    def test_non_ciphertext_rejected(self):
        with self.assertRaises(TypeError):
            self.fhe.decrypt("not-a-ct")
        with self.assertRaises(TypeError):
            self.fhe.add("x", self.fhe.encrypt(1, 0), 1)

    def test_noise_budget(self):
        deep = self.fhe.encrypt(1, 0)
        for _ in range(3):
            deep = self.fhe.multiply(deep, deep, 1)
        self.assertGreater(deep.noise, MAX_NOISE)
        with self.assertRaises(NoiseExceededError):
            self.fhe.decrypt(deep)


class TestEvaluate(unittest.TestCase):
    def setUp(self):
        self.fhe = FHE(SEED_A)

    def test_dot_product(self):
        # (2*3) + (4*5) = 26
        ins = [self.fhe.encrypt(v, i) for i, v in enumerate((2, 3, 4, 5))]
        prog = [EvalOp("mul", 0, 1), EvalOp("mul", 2, 3), EvalOp("add", 4, 5)]
        final, report = self.fhe.evaluate(prog, ins, 9)
        self.assertEqual(self.fhe.decrypt(final), 26)
        self.assertEqual(report.ops, 3)
        self.assertEqual(report.input_count, 4)
        self.assertEqual(report.final_noise, final.noise)
        self.assertTrue(report.digest.startswith("sha256:"))

    def test_empty_inputs_rejected(self):
        with self.assertRaises(TypeError):
            self.fhe.evaluate([EvalOp("add", 0, 1)], [], 0)

    def test_bad_op_index(self):
        ins = [self.fhe.encrypt(1, 0)]
        with self.assertRaises(FHEError):
            self.fhe.evaluate([EvalOp("add", 0, 5)], ins, 0)

    def test_bad_op_kind(self):
        with self.assertRaises(FHEError):
            EvalOp("sub", 0, 1)

    def test_op_bad_indices(self):
        with self.assertRaises(FHEError):
            EvalOp("add", -1, 0)
        with self.assertRaises(FHEError):
            EvalOp("add", True, 0)

    def test_non_evalop_rejected(self):
        ins = [self.fhe.encrypt(1, 0), self.fhe.encrypt(2, 1)]
        with self.assertRaises(TypeError):
            self.fhe.evaluate([("add", 0, 1)], ins, 0)

    def test_report_as_dict(self):
        ins = [self.fhe.encrypt(1, 0), self.fhe.encrypt(2, 1)]
        _, report = self.fhe.evaluate([EvalOp("add", 0, 1)], ins, 0)
        d = report.as_dict()
        self.assertEqual(d["schema"], FHE_INTERFACE_SCHEMA)
        self.assertEqual(d["ops"], 1)
        self.assertIsInstance(report, EvalReport)


class TestAuditEvent(unittest.TestCase):
    def test_shapes(self):
        for kind in ("keygen", "encrypt", "decrypt", "eval", "integrity-failed", "noise-exceeded"):
            ev = fhe_audit_event(kind, 7, detail="x")
            self.assertEqual(ev["schema"], "audit.ndjson/1")
            self.assertEqual(ev["kind"], f"fhe-interface.{kind}")
            self.assertEqual(ev["module"], FHE_INTERFACE_SCHEMA)
            self.assertEqual(ev["seq"], 7)

    def test_bad_kind(self):
        with self.assertRaises(ValueError):
            fhe_audit_event("bogus", 0)

    def test_bad_seq(self):
        with self.assertRaises(ValueError):
            fhe_audit_event("encrypt", -1)
        with self.assertRaises(ValueError):
            fhe_audit_event("encrypt", True)

    def test_bad_detail(self):
        with self.assertRaises(TypeError):
            fhe_audit_event("encrypt", 0, detail=42)


class TestMain(unittest.TestCase):
    def test_main(self):
        fhe_main()


if __name__ == "__main__":
    unittest.main()
