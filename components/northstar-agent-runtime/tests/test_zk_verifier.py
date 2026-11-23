"""Tests for zk_verifier: statement binding, key scoping, fail-closed verify."""

import hashlib
import hmac
import unittest

from zk_verifier import (
    SCHEMA_PIN,
    ZK_VERIFIER_VERSION,
    ZKProof,
    VerifyReport,
    bind_statement,
    make_proof,
    seal_with_key,
    verify,
    verify_detailed,
)


def _valid_proof(**kw):
    return make_proof("range-check.v1", {"x": 42, "max": 100}, **kw)


class TestPins(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(ZK_VERIFIER_VERSION, "zk-verifier.v1")

    def test_schema_pin(self):
        self.assertEqual(SCHEMA_PIN, "northstar.zk-verifier.v1")

    def test_proof_carries_schema_pin(self):
        self.assertEqual(_valid_proof().schema, SCHEMA_PIN)


class TestConstructor(unittest.TestCase):
    def test_frozen(self):
        p = _valid_proof()
        with self.assertRaises(Exception):
            p.circuit_id = "other"  # type: ignore[misc]

    def test_empty_proof_bytes_rejected(self):
        with self.assertRaises(ValueError):
            ZKProof(proof_bytes=b"", public_inputs={}, circuit_id="c")

    def test_non_bytes_proof_rejected(self):
        with self.assertRaises(TypeError):
            ZKProof(proof_bytes="not-bytes", public_inputs={}, circuit_id="c")  # type: ignore[arg-type]

    def test_oversized_proof_rejected(self):
        with self.assertRaises(ValueError):
            ZKProof(proof_bytes=b"\x00" * ((1 << 20) + 1), public_inputs={}, circuit_id="c")

    def test_empty_circuit_id_rejected(self):
        with self.assertRaises(ValueError):
            ZKProof(proof_bytes=b"\x00" * 32, public_inputs={}, circuit_id="")

    def test_non_str_circuit_id_rejected(self):
        with self.assertRaises(TypeError):
            ZKProof(proof_bytes=b"\x00" * 32, public_inputs={}, circuit_id=123)  # type: ignore[arg-type]

    def test_non_mapping_inputs_rejected(self):
        with self.assertRaises(TypeError):
            ZKProof(proof_bytes=b"\x00" * 32, public_inputs=[1, 2], circuit_id="c")  # type: ignore[arg-type]

    def test_non_str_input_key_rejected(self):
        with self.assertRaises(TypeError):
            ZKProof(proof_bytes=b"\x00" * 32, public_inputs={1: "x"}, circuit_id="c")  # type: ignore[dict-item]

    def test_non_canonicalizable_inputs_rejected(self):
        with self.assertRaises(ValueError):
            ZKProof(proof_bytes=b"\x00" * 32, public_inputs={"x": object()}, circuit_id="c")

    def test_wrong_schema_rejected(self):
        with self.assertRaises(ValueError):
            ZKProof(proof_bytes=b"\x00" * 32, public_inputs={}, circuit_id="c",
                    schema="wrong")


class TestBindStatement(unittest.TestCase):
    def test_deterministic(self):
        a = bind_statement("c", {"x": 1})
        b = bind_statement("c", {"x": 1})
        self.assertEqual(a, b)
        self.assertEqual(len(a), 32)

    def test_differs_on_circuit(self):
        self.assertNotEqual(bind_statement("c1", {"x": 1}), bind_statement("c2", {"x": 1}))

    def test_differs_on_inputs(self):
        self.assertNotEqual(bind_statement("c", {"x": 1}), bind_statement("c", {"x": 2}))

    def test_key_order_irrelevant(self):
        # Canonical encoding: mapping order must not change the digest.
        a = bind_statement("c", {"x": 1, "y": 2})
        b = bind_statement("c", {"y": 2, "x": 1})
        self.assertEqual(a, b)

    def test_nested_inputs(self):
        d = bind_statement("c", {"a": {"b": [1, 2, {"c": None}]}})
        self.assertEqual(len(d), 32)

    def test_bad_circuit_rejected(self):
        with self.assertRaises(ValueError):
            bind_statement("", {"x": 1})


class TestVerify(unittest.TestCase):
    def test_valid_proof_verifies(self):
        self.assertTrue(verify(_valid_proof()))

    def test_tampered_binding_fails(self):
        p = _valid_proof()
        bad = ZKProof(proof_bytes=b"\xff" * 32 + p.proof_bytes[32:],
                      public_inputs=dict(p.public_inputs), circuit_id=p.circuit_id)
        self.assertFalse(verify(bad))

    def test_short_proof_fails(self):
        p = ZKProof(proof_bytes=b"\x00" * 10, public_inputs={}, circuit_id="c")
        self.assertFalse(verify(p))

    def test_statement_substitution_fails(self):
        # Same proof bytes, different claimed public inputs.
        p = _valid_proof()
        sub = ZKProof(proof_bytes=p.proof_bytes,
                      public_inputs={"x": 4200, "max": 100},
                      circuit_id=p.circuit_id)
        self.assertFalse(verify(sub))

    def test_circuit_substitution_fails(self):
        p = _valid_proof()
        sub = ZKProof(proof_bytes=p.proof_bytes,
                      public_inputs=dict(p.public_inputs),
                      circuit_id="other-circuit.v1")
        self.assertFalse(verify(sub))

    def test_non_proof_raises_type_error(self):
        with self.assertRaises(TypeError):
            verify("not-a-proof")  # type: ignore[arg-type]

    def test_sealed_verifies_under_key(self):
        key = b"deployment-key"
        p = make_proof("c", {"x": 1}, verification_key=key)
        self.assertTrue(p.has_seal())
        self.assertTrue(verify(p, verification_key=key))

    def test_sealed_fails_under_wrong_key(self):
        key = b"deployment-key"
        p = make_proof("c", {"x": 1}, verification_key=key)
        self.assertFalse(verify(p, verification_key=b"wrong-key"))

    def test_unsealed_with_key_fails_mac_absent(self):
        # Unsealed proof is too short for a MAC when a key is demanded.
        p = make_proof("c", {"x": 1}, body=b"tiny")
        self.assertFalse(p.has_seal())
        self.assertFalse(verify(p, verification_key=b"some-key"))

    def test_seal_with_key_construction(self):
        key = b"k"
        raw = bind_statement("c", {"x": 1}) + b"body"
        sealed = seal_with_key(raw, key)
        expected_tag = hmac.new(key, raw, hashlib.sha256).digest()
        self.assertEqual(sealed[-32:], expected_tag)

    def test_seal_bad_key_rejected(self):
        with self.assertRaises(TypeError):
            seal_with_key(b"raw", "not-bytes")  # type: ignore[arg-type]


class TestVerifyDetailed(unittest.TestCase):
    def test_report_shape(self):
        r = verify_detailed(_valid_proof())
        self.assertIsInstance(r, VerifyReport)
        self.assertTrue(r.valid)
        self.assertIn("binding-ok", r.reasons)
        d = r.as_dict()
        self.assertEqual(d["schema"], SCHEMA_PIN)
        self.assertEqual(d["version"], ZK_VERIFIER_VERSION)
        self.assertEqual(d["circuit_id"], "range-check.v1")

    def test_report_reasons_on_failure(self):
        p = _valid_proof()
        sub = ZKProof(proof_bytes=p.proof_bytes,
                      public_inputs={"x": 9}, circuit_id=p.circuit_id)
        r = verify_detailed(sub)
        self.assertFalse(r.valid)
        self.assertIn("binding-mismatch", r.reasons)

    def test_report_mac_reasons(self):
        key = b"k"
        p = make_proof("c", {"x": 1}, verification_key=key)
        r = verify_detailed(p, verification_key=b"wrong")
        self.assertFalse(r.valid)
        self.assertIn("binding-ok", r.reasons)
        self.assertIn("mac-mismatch", r.reasons)


class TestMain(unittest.TestCase):
    def test_main_runs(self):
        import zk_verifier
        zk_verifier.main()  # asserts internally; must not raise


if __name__ == "__main__":
    unittest.main()
