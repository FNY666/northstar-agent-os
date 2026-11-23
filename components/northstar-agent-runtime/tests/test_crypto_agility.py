"""Tests for the crypto-agility seam (crypto_agility.py)."""

import unittest

from crypto_agility import (
    ALGORITHM_ED25519,
    ALGORITHM_ML_DSA_65,
    Ed25519Signer,
    Ed25519Verifier,
    Signer,
    UnknownAlgorithmError,
    Verifier,
    get_signer,
    get_verifier,
    register_algorithm,
    supported_algorithms,
)

_SEED_A = bytes(range(32))
_SEED_B = bytes([255 - i for i in range(32)])


class Ed25519SeamTests(unittest.TestCase):
    def test_roundtrip(self):
        signer = Ed25519Signer(_SEED_A)
        verifier = Ed25519Verifier(signer.public_key_bytes())
        sig = signer.sign(b"northstar policy digest")
        self.assertTrue(verifier.verify(b"northstar policy digest", sig))

    def test_wrong_key_fails(self):
        signer = Ed25519Signer(_SEED_A)
        wrong = Ed25519Verifier(Ed25519Signer(_SEED_B).public_key_bytes())
        sig = signer.sign(b"hello")
        self.assertFalse(wrong.verify(b"hello", sig))

    def test_tampered_message_fails(self):
        signer = Ed25519Signer(_SEED_A)
        verifier = Ed25519Verifier(signer.public_key_bytes())
        sig = signer.sign(b"allow:bash")
        self.assertFalse(verifier.verify(b"allow:rm", sig))

    def test_tampered_signature_fails(self):
        signer = Ed25519Signer(_SEED_A)
        verifier = Ed25519Verifier(signer.public_key_bytes())
        sig = bytearray(signer.sign(b"data"))
        sig[0] ^= 0xFF
        self.assertFalse(verifier.verify(b"data", bytes(sig)))

    def test_algorithm_identifier(self):
        signer = Ed25519Signer(_SEED_A)
        verifier = Ed25519Verifier(signer.public_key_bytes())
        self.assertEqual(signer.algorithm, ALGORITHM_ED25519)
        self.assertEqual(verifier.algorithm, ALGORITHM_ED25519)
        self.assertEqual(ALGORITHM_ED25519, "ed25519")

    def test_verify_never_raises_on_garbage(self):
        signer = Ed25519Signer(_SEED_A)
        verifier = Ed25519Verifier(signer.public_key_bytes())
        good = signer.sign(b"ok")
        for bad_sig in (b"", b"short", bytes(64), good[:-1] + b"x", None):
            self.assertFalse(verifier.verify(b"ok", bad_sig))
        self.assertFalse(verifier.verify(None, good))
        self.assertFalse(verifier.verify("not bytes", good))

    def test_bad_key_material_rejected(self):
        for bad in (b"", bytes(31), bytes(33), "seed", None):
            with self.assertRaises(ValueError):
                Ed25519Signer(bad)
            with self.assertRaises(ValueError):
                Ed25519Verifier(bad)


class RegistryTests(unittest.TestCase):
    def test_supported_algorithms_contains_ed25519(self):
        self.assertIn(ALGORITHM_ED25519, supported_algorithms())

    def test_registry_lookup_roundtrip(self):
        signer = get_signer(ALGORITHM_ED25519, _SEED_A)
        self.assertIsInstance(signer, Signer)
        self.assertEqual(signer.algorithm, ALGORITHM_ED25519)
        verifier = get_verifier(ALGORITHM_ED25519, signer.public_key_bytes())
        self.assertIsInstance(verifier, Verifier)
        sig = signer.sign(b"via registry")
        self.assertTrue(verifier.verify(b"via registry", sig))

    def test_unknown_algorithm_raises(self):
        with self.assertRaises(UnknownAlgorithmError):
            get_signer("rsa-pss-sha256", bytes(32))
        with self.assertRaises(UnknownAlgorithmError):
            get_verifier("rsa-pss-sha256", bytes(32))

    def test_reserved_ml_dsa_65_fails_loudly(self):
        # Must not silently fall back to Ed25519.
        self.assertEqual(ALGORITHM_ML_DSA_65, "ml-dsa-65")
        with self.assertRaises(NotImplementedError):
            get_signer(ALGORITHM_ML_DSA_65, bytes(32))
        with self.assertRaises(NotImplementedError):
            get_verifier(ALGORITHM_ML_DSA_65, bytes(32))

    def test_custom_algorithm_registration(self):
        # The seam is algorithm-agnostic: a future ML-DSA or hybrid registers
        # here with zero changes to call sites. Stub uses XOR "signatures".
        class XorSigner(Signer):
            def __init__(self, key: bytes):
                self._key = bytes(key)

            @property
            def algorithm(self):
                return "xor-test"

            def public_key_bytes(self):
                return self._key

            def sign(self, message: bytes) -> bytes:
                return bytes(b ^ self._key[i % len(self._key)] for i, b in enumerate(message))

        class XorVerifier(Verifier):
            def __init__(self, key: bytes):
                self._key = bytes(key)

            @property
            def algorithm(self):
                return "xor-test"

            def verify(self, message: bytes, signature: bytes) -> bool:
                try:
                    return XorSigner(self._key).sign(message) == signature
                except Exception:
                    return False

        register_algorithm("xor-test", XorSigner, XorVerifier)
        try:
            signer = get_signer("xor-test", b"k")
            verifier = get_verifier("xor-test", signer.public_key_bytes())
            sig = signer.sign(b"agility")
            self.assertTrue(verifier.verify(b"agility", sig))
            self.assertFalse(verifier.verify(b"agility", b"wrong"))
            self.assertIn("xor-test", supported_algorithms())
        finally:
            # Restore the pristine registry: re-registering replaces entries,
            # so drop the test stub.
            import crypto_agility

            crypto_agility._REGISTRY.pop("xor-test", None)

    def test_register_rejects_empty_name(self):
        with self.assertRaises(ValueError):
            register_algorithm("", Ed25519Signer, Ed25519Verifier)


if __name__ == "__main__":
    unittest.main()
