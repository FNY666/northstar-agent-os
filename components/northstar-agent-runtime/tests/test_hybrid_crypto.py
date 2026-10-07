"""Tests for hybrid_crypto: Ed25519-style Schnorr || Dilithium-style lattice (simulated)."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import hybrid_crypto as hc
from hybrid_crypto import (
    HYBRID_CRYPTO_VERSION,
    HYBRID_CRYPTO_SCHEMA,
    HybridCryptoError,
    HybridPublicKey,
    HybridSecretKey,
    HybridSignature,
    KeygenError,
    SignError,
    VerifyInputError,
    hybrid_audit_event,
    keygen,
    sign,
    verify,
)


def _keys(seed: bytes = b"test-seed"):
    return keygen(seed)


class TestPins(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(HYBRID_CRYPTO_VERSION, "hybrid-crypto.v1")

    def test_schema_pin(self):
        self.assertEqual(HYBRID_CRYPTO_SCHEMA, "northstar.hybrid-crypto.v1")


class TestKeygen(unittest.TestCase):
    def test_keygen_returns_pair(self):
        public, secret = _keys()
        self.assertIsInstance(public, HybridPublicKey)
        self.assertIsInstance(secret, HybridSecretKey)
        self.assertEqual(public.key_id, secret.key_id)

    def test_keygen_deterministic(self):
        p1, s1 = _keys(b"same")
        p2, s2 = _keys(b"same")
        self.assertEqual(p1, p2)
        self.assertEqual(s1.classical_sk, s2.classical_sk)
        self.assertEqual(s1.pq_sk, s2.pq_sk)

    def test_keygen_seed_separation(self):
        p1, _ = _keys(b"seed-a")
        p2, _ = _keys(b"seed-b")
        self.assertNotEqual(p1.key_id, p2.key_id)
        self.assertNotEqual(p1.classical_pk, p2.classical_pk)
        self.assertNotEqual(p1.pq_pk, p2.pq_pk)

    def test_public_derivation_matches(self):
        public, secret = _keys()
        self.assertEqual(secret.public(), public)

    def test_secret_as_dict_hides_secrets(self):
        _, secret = _keys()
        d = secret.as_dict()
        self.assertEqual(d["schema"], HYBRID_CRYPTO_SCHEMA)
        self.assertIn("seed_digest", d)
        self.assertNotIn("seed", d)
        self.assertNotIn("classical_sk", d)
        self.assertNotIn("pq_sk", d)
        # The digest pins the seed without revealing it.
        self.assertTrue(d["seed_digest"].startswith("sha256:"))

    def test_bad_seed_types(self):
        for bad in ("str-seed", None, 123, True, bytearray(b"x")):
            with self.assertRaises((TypeError, KeygenError)):
                keygen(bad)

    def test_empty_seed_rejected(self):
        with self.assertRaises(ValueError):
            keygen(b"")

    def test_oversize_seed_rejected(self):
        with self.assertRaises(KeygenError):
            keygen(b"x" * 1025)


class TestSignVerify(unittest.TestCase):
    def test_roundtrip(self):
        public, secret = _keys()
        sig = sign(secret, b"hello")
        self.assertIsInstance(sig, HybridSignature)
        self.assertTrue(verify(public, b"hello", sig))

    def test_sign_deterministic(self):
        _, secret = _keys()
        self.assertEqual(sign(secret, b"m"), sign(secret, b"m"))

    def test_message_sensitivity(self):
        public, secret = _keys()
        sig = sign(secret, b"m1")
        self.assertFalse(verify(public, b"m2", sig))

    def test_empty_message_signs(self):
        # Empty bytes are a valid (pinned) message; only non-bytes fail.
        public, secret = _keys()
        sig = sign(secret, b"")
        self.assertTrue(verify(public, b"", sig))

    def test_wrong_key_fails(self):
        public, secret = _keys(b"signer")
        other_public, _ = _keys(b"other")
        sig = sign(secret, b"m")
        self.assertFalse(verify(other_public, b"m", sig))

    def test_tampered_classical_half_fails(self):
        public, secret = _keys()
        sig = sign(secret, b"m")
        r, z = sig.classical_sig
        bad = HybridSignature(
            key_id=sig.key_id,
            message_digest=sig.message_digest,
            classical_sig=(r, (z + 1) % hc._C_Q),
            pq_sig=sig.pq_sig,
        )
        self.assertFalse(verify(public, b"m", bad))

    def test_tampered_pq_half_fails(self):
        public, secret = _keys()
        sig = sign(secret, b"m")
        (z0, z1), c = sig.pq_sig
        bad = HybridSignature(
            key_id=sig.key_id,
            message_digest=sig.message_digest,
            classical_sig=sig.classical_sig,
            pq_sig=((z0 + 1, z1), c),
        )
        self.assertFalse(verify(public, b"m", bad))

    def test_halves_cannot_mix_across_messages(self):
        # Nested binding: the PQ half commits to the classical half, so a
        # classical half from message B cannot ride under message A's PQ half.
        public, secret = _keys()
        sig_a = sign(secret, b"message A")
        sig_b = sign(secret, b"message B")
        mixed = HybridSignature(
            key_id=sig_a.key_id,
            message_digest=sig_a.message_digest,
            classical_sig=sig_b.classical_sig,
            pq_sig=sig_a.pq_sig,
        )
        self.assertFalse(verify(public, b"message A", mixed))

    def test_key_id_mismatch_fails(self):
        public, secret = _keys()
        sig = sign(secret, b"m")
        other_public, _ = _keys(b"other")
        forged = HybridSignature(
            key_id=other_public.key_id,
            message_digest=sig.message_digest,
            classical_sig=sig.classical_sig,
            pq_sig=sig.pq_sig,
        )
        self.assertFalse(verify(public, b"m", forged))

    def test_message_digest_mismatch_fails(self):
        public, secret = _keys()
        sig = sign(secret, b"m")
        forged = HybridSignature(
            key_id=sig.key_id,
            message_digest="sha256:" + "00" * 32,
            classical_sig=sig.classical_sig,
            pq_sig=sig.pq_sig,
        )
        self.assertFalse(verify(public, b"m", forged))

    def test_classical_only_is_not_hybrid(self):
        # A lone classical signature verifies classically but has no PQ
        # half -- it can never satisfy the hybrid verifier.
        public, secret = _keys()
        lone = hc._classical_sign(secret.classical_sk, b"m")
        self.assertTrue(hc._classical_verify(public.classical_pk, b"m", lone))
        # There is no HybridSignature wrapping it, and verify() demands one.
        with self.assertRaises(VerifyInputError):
            verify(public, b"m", lone)

    def test_sign_bad_secret_type(self):
        with self.assertRaises(SignError):
            sign("not-a-key", b"m")

    def test_sign_bad_message_type(self):
        _, secret = _keys()
        for bad in ("str", None, 123, True):
            with self.assertRaises(TypeError):
                sign(secret, bad)

    def test_verify_bad_input_types(self):
        public, secret = _keys()
        sig = sign(secret, b"m")
        with self.assertRaises(VerifyInputError):
            verify("not-a-key", b"m", sig)
        with self.assertRaises(VerifyInputError):
            verify(public, b"m", "not-a-sig")

    def test_verify_bad_message_type(self):
        public, secret = _keys()
        sig = sign(secret, b"m")
        with self.assertRaises(TypeError):
            verify(public, "str-message", sig)


class TestRecords(unittest.TestCase):
    def test_public_key_validation(self):
        with self.assertRaises(TypeError):
            HybridPublicKey(key_id="", classical_pk=1, pq_pk=(1, 2))
        with self.assertRaises(TypeError):
            HybridPublicKey(key_id="k", classical_pk=True, pq_pk=(1, 2))
        with self.assertRaises(TypeError):
            HybridPublicKey(key_id="k", classical_pk=1, pq_pk=(1,))

    def test_signature_validation(self):
        public, secret = _keys()
        sig = sign(secret, b"m")
        with self.assertRaises(TypeError):
            HybridSignature(
                key_id="",
                message_digest=sig.message_digest,
                classical_sig=sig.classical_sig,
                pq_sig=sig.pq_sig,
            )
        with self.assertRaises(TypeError):
            HybridSignature(
                key_id="k",
                message_digest="not-a-pin",
                classical_sig=sig.classical_sig,
                pq_sig=sig.pq_sig,
            )
        with self.assertRaises(TypeError):
            HybridSignature(
                key_id="k",
                message_digest=sig.message_digest,
                classical_sig=(1,),
                pq_sig=sig.pq_sig,
            )
        with self.assertRaises(TypeError):
            HybridSignature(
                key_id="k",
                message_digest=sig.message_digest,
                classical_sig=sig.classical_sig,
                pq_sig=((1, 2), True),
            )

    def test_records_frozen(self):
        public, secret = _keys()
        sig = sign(secret, b"m")
        import dataclasses

        with self.assertRaises(dataclasses.FrozenInstanceError):
            public.key_id = "x"
        with self.assertRaises(dataclasses.FrozenInstanceError):
            sig.message_digest = "x"

    def test_as_dict_shapes(self):
        public, secret = _keys()
        sig = sign(secret, b"m")
        pd = public.as_dict()
        self.assertEqual(pd["schema"], HYBRID_CRYPTO_SCHEMA)
        self.assertTrue(pd["classical_pk"].startswith("0x"))
        self.assertEqual(len(pd["pq_pk"]), 2)
        sd = sig.as_dict()
        self.assertEqual(sd["schema"], HYBRID_CRYPTO_SCHEMA)
        self.assertTrue(sd["message_digest"].startswith("sha256:"))

    def test_wire_bytes_deterministic(self):
        _, secret = _keys()
        sig = sign(secret, b"m")
        self.assertEqual(sig.wire_bytes(), sig.wire_bytes())
        other = sign(secret, b"m2")
        self.assertNotEqual(sig.wire_bytes(), other.wire_bytes())


class TestAuditEvents(unittest.TestCase):
    def test_event_shapes(self):
        public, secret = _keys()
        sig = sign(secret, b"m")
        for kind, record in (
            ("hybrid-keygen", public),
            ("hybrid-keygen", secret),
            ("hybrid-signed", sig),
            ("hybrid-verified", sig),
            ("hybrid-rejected", sig),
        ):
            event = hybrid_audit_event(kind, record, 7)
            self.assertEqual(event["schema"], "northstar.audit.ndjson/1")
            self.assertEqual(event["event"], kind)
            self.assertEqual(event["module"], HYBRID_CRYPTO_VERSION)
            self.assertEqual(event["audit_seq"], 7)
            self.assertEqual(
                event["record"]["schema"], HYBRID_CRYPTO_SCHEMA
            )

    def test_bad_kind_rejected(self):
        public, _ = _keys()
        with self.assertRaises(ValueError):
            hybrid_audit_event("nope", public, 1)

    def test_bad_record_rejected(self):
        with self.assertRaises(TypeError):
            hybrid_audit_event("hybrid-signed", {"not": "a record"}, 1)

    def test_bad_seq_rejected(self):
        public, _ = _keys()
        with self.assertRaises(TypeError):
            hybrid_audit_event("hybrid-signed", public, True)
        with self.assertRaises(ValueError):
            hybrid_audit_event("hybrid-signed", public, -1)


class TestMain(unittest.TestCase):
    def test_main_self_check(self):
        # main() asserts internally; silence its print.
        import io
        from contextlib import redirect_stdout

        with redirect_stdout(io.StringIO()):
            hc.main()


class TestComponentProperties(unittest.TestCase):
    def test_pq_norm_bound_holds(self):
        # Honest PQ signatures always satisfy the verifier's norm bound.
        _, secret = _keys()
        for msg in (b"a", b"b", b"c"):
            sig = sign(secret, msg)
            (z0, z1), _ = sig.pq_sig
            self.assertLess(abs(z0), hc._PQ_GAMMA1)
            self.assertLess(abs(z1), hc._PQ_GAMMA1)

    def test_group_params_sane(self):
        # Deterministically generated safe prime: 128-bit, q prime, g^q == 1.
        self.assertEqual(hc._C_P.bit_length(), 128)
        self.assertEqual(hc._C_Q, (hc._C_P - 1) // 2)
        self.assertEqual(pow(hc._C_G, hc._C_Q, hc._C_P), 1)


if __name__ == "__main__":
    unittest.main()
