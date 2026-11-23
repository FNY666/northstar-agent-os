"""Tests for fhe_wrapper (simulated homomorphic-encryption interface)."""

import dataclasses
import unittest

from fhe_wrapper import (
    ADD_NOISE,
    FHE_WRAPPER_VERSION,
    MAX_NOISE,
    SCHEMA_PIN,
    ContextMismatchError,
    FHECiphertext,
    FHEContext,
    FHEError,
    FHEScheme,
    IntegrityError,
    NoiseExhaustedError,
)


class TestVersionPin(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(FHE_WRAPPER_VERSION, "fhe-wrapper.v1")
        self.assertEqual(SCHEMA_PIN, "northstar.fhe-wrapper.v1")


class TestContext(unittest.TestCase):
    def test_frozen(self):
        ctx = FHEContext(scheme=FHEScheme.BFV, key_id="k1")
        with self.assertRaises(dataclasses.FrozenInstanceError):
            ctx.key_id = "k2"  # type: ignore[misc]

    def test_empty_key_id_rejected(self):
        with self.assertRaises(FHEError):
            FHEContext(scheme=FHEScheme.BFV, key_id="")

    def test_non_str_key_id_rejected(self):
        with self.assertRaises(FHEError):
            FHEContext(scheme=FHEScheme.BFV, key_id=123)  # type: ignore[arg-type]

    def test_bad_scheme_rejected(self):
        with self.assertRaises(FHEError):
            FHEContext(scheme="bfv", key_id="k1")  # type: ignore[arg-type]


class TestEncryptDecrypt(unittest.TestCase):
    def setUp(self):
        self.ctx = FHEContext(scheme=FHEScheme.BFV, key_id="k1")

    def test_roundtrip(self):
        c = self.ctx.encrypt(42, seq=1)
        self.assertIsInstance(c, FHECiphertext)
        self.assertEqual(self.ctx.decrypt(c), 42)

    def test_fresh_noise_zero(self):
        c = self.ctx.encrypt(7, seq=1)
        self.assertEqual(c.noise, 0)

    def test_deterministic(self):
        a = self.ctx.encrypt(5, seq=9)
        b = self.ctx.encrypt(5, seq=9)
        self.assertEqual(a, b)

    def test_bool_rejected(self):
        with self.assertRaises(FHEError):
            self.ctx.encrypt(True, seq=1)  # type: ignore[arg-type]

    def test_non_int_rejected(self):
        with self.assertRaises(FHEError):
            self.ctx.encrypt(3.5, seq=1)  # type: ignore[arg-type]
        with self.assertRaises(FHEError):
            self.ctx.encrypt("5", seq=1)  # type: ignore[arg-type]

    def test_ciphertext_frozen(self):
        c = self.ctx.encrypt(1, seq=1)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            c.value = 999  # type: ignore[misc]

    def test_decrypt_wrong_context(self):
        other = FHEContext(scheme=FHEScheme.BFV, key_id="k2")
        c = self.ctx.encrypt(1, seq=1)
        with self.assertRaises(ContextMismatchError):
            other.decrypt(c)

    def test_decrypt_wrong_scheme_context(self):
        other = FHEContext(scheme=FHEScheme.BGV, key_id="k1")
        c = self.ctx.encrypt(1, seq=1)
        with self.assertRaises(ContextMismatchError):
            other.decrypt(c)

    def test_tampered_value_detected(self):
        c = self.ctx.encrypt(1, seq=1)
        tampered = dataclasses.replace(c, value=999)
        with self.assertRaises(IntegrityError):
            self.ctx.decrypt(tampered)

    def test_tampered_noise_detected(self):
        c = self.ctx.encrypt(1, seq=1)
        tampered = dataclasses.replace(c, noise=50)
        with self.assertRaises(IntegrityError):
            self.ctx.decrypt(tampered)


class TestAdd(unittest.TestCase):
    def setUp(self):
        self.ctx = FHEContext(scheme=FHEScheme.BFV, key_id="k1")

    def test_add_correctness(self):
        c1 = self.ctx.encrypt(40, seq=1)
        c2 = self.ctx.encrypt(2, seq=2)
        self.assertEqual(self.ctx.decrypt(self.ctx.add(c1, c2)), 42)

    def test_add_noise_grows(self):
        c1 = self.ctx.encrypt(1, seq=1)
        c2 = self.ctx.encrypt(1, seq=2)
        total = self.ctx.add(c1, c2)
        self.assertEqual(total.noise, ADD_NOISE)

    def test_chained_adds(self):
        total = self.ctx.encrypt(0, seq=0)
        for i in range(10):
            total = self.ctx.add(total, self.ctx.encrypt(1, seq=100 + i))
        self.assertEqual(self.ctx.decrypt(total), 10)

    def test_add_cross_context_rejected(self):
        other = FHEContext(scheme=FHEScheme.BFV, key_id="k2")
        c1 = self.ctx.encrypt(1, seq=1)
        c2 = other.encrypt(1, seq=1)
        with self.assertRaises((ContextMismatchError, IntegrityError, FHEError)):
            self.ctx.add(c1, c2)

    def test_add_cross_scheme_rejected(self):
        other = FHEContext(scheme=FHEScheme.TFHE, key_id="k1")
        c1 = self.ctx.encrypt(1, seq=1)
        c2 = other.encrypt(1, seq=1)
        with self.assertRaises((ContextMismatchError, IntegrityError, FHEError)):
            self.ctx.add(c1, c2)

    def test_add_non_ciphertext_rejected(self):
        c1 = self.ctx.encrypt(1, seq=1)
        with self.assertRaises(FHEError):
            self.ctx.add(c1, "not-a-ciphertext")  # type: ignore[arg-type]

    def test_noise_exhaustion_fail_closed(self):
        deep = self.ctx.encrypt(0, seq=0)
        for i in range(MAX_NOISE + 2):
            deep = self.ctx.add(deep, self.ctx.encrypt(0, seq=1000 + i))
        self.assertGreater(deep.noise, MAX_NOISE)
        with self.assertRaises(NoiseExhaustedError):
            self.ctx.decrypt(deep)

    def test_as_dict_schema(self):
        c = self.ctx.encrypt(3, seq=1)
        d = c.as_dict()
        self.assertEqual(d["schema"], SCHEMA_PIN)
        self.assertEqual(d["scheme"], "bfv")
        self.assertEqual(d["key_id"], "k1")


class TestMain(unittest.TestCase):
    def test_main_runs(self):
        import fhe_wrapper

        fhe_wrapper.main()


if __name__ == "__main__":
    unittest.main()
