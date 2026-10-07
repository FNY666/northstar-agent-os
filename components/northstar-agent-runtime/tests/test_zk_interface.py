"""Tests for zk_interface: ZK prover (prove/verify), simulated."""

import sys
import unittest

sys.path.insert(0, "..")

from zk_interface import (
    SCHEMA_PIN,
    ZK_INTERFACE_VERSION,
    ZKInterfaceError,
    ZKProof,
    ZKProver,
    Statement,
    StatementVerifyReport,
    verify,
    verify_detailed,
    witness_pin,
    zk_audit_event,
)


def _stmt(circuit="kyc-check.v1", inputs=None):
    return Statement(circuit, inputs if inputs is not None else {"age_over": 18})


class TestPins(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(ZK_INTERFACE_VERSION, "zk-interface.v1")

    def test_schema_pin(self):
        self.assertEqual(SCHEMA_PIN, "northstar.zk-interface.v1")


class TestStatement(unittest.TestCase):
    def test_frozen(self):
        s = _stmt()
        with self.assertRaises(Exception):
            s.circuit_id = "x"  # type: ignore[misc]

    def test_empty_circuit_rejected(self):
        with self.assertRaises(ValueError):
            Statement("", {"a": 1})

    def test_bool_circuit_rejected(self):
        with self.assertRaises(TypeError):
            Statement(True, {"a": 1})  # type: ignore[arg-type]

    def test_non_mapping_inputs_rejected(self):
        with self.assertRaises(TypeError):
            Statement("c", [1, 2])  # type: ignore[arg-type]

    def test_non_str_key_rejected(self):
        with self.assertRaises(TypeError):
            Statement("c", {1: "x"})  # type: ignore[dict-item]

    def test_non_canonicalizable_inputs_rejected(self):
        with self.assertRaises(ValueError):
            Statement("c", {"a": float("nan")})

    def test_binding_deterministic(self):
        self.assertEqual(_stmt().binding(), _stmt().binding())

    def test_binding_key_order_independent(self):
        a = Statement("c", {"x": 1, "y": 2})
        b = Statement("c", {"y": 2, "x": 1})
        self.assertEqual(a.binding(), b.binding())

    def test_binding_changes_with_inputs(self):
        a = Statement("c", {"x": 1})
        b = Statement("c", {"x": 2})
        self.assertNotEqual(a.binding(), b.binding())

    def test_as_dict(self):
        d = _stmt().as_dict()
        self.assertEqual(d["schema"], SCHEMA_PIN)
        self.assertTrue(d["binding"].startswith("sha256:"))


class TestProve(unittest.TestCase):
    def test_prove_happy_path(self):
        prover = ZKProver("kyc-check.v1")
        proof = prover.prove(_stmt(), {"w": 1})
        self.assertIsInstance(proof, ZKProof)
        self.assertEqual(proof.circuit_id, "kyc-check.v1")
        self.assertEqual(dict(proof.public_inputs), {"age_over": 18})

    def test_binding_prefix_matches_statement(self):
        stmt = _stmt()
        proof = ZKProver("kyc-check.v1").prove(stmt, {"w": 1})
        self.assertEqual(proof.proof_bytes[:32], stmt.binding())

    def test_witness_never_raw(self):
        stmt = _stmt()
        proof = ZKProver("kyc-check.v1").prove(stmt, {"secret": "hunter2"})
        self.assertNotIn(b"hunter2", proof.proof_bytes)

    def test_deterministic(self):
        stmt = _stmt()
        p1 = ZKProver("kyc-check.v1").prove(stmt, {"w": 1})
        p2 = ZKProver("kyc-check.v1").prove(stmt, {"w": 1})
        self.assertEqual(p1.proof_bytes, p2.proof_bytes)

    def test_different_witness_different_proof(self):
        stmt = _stmt()
        p1 = ZKProver("kyc-check.v1").prove(stmt, {"w": 1})
        p2 = ZKProver("kyc-check.v1").prove(stmt, {"w": 2})
        self.assertNotEqual(p1.proof_bytes, p2.proof_bytes)

    def test_circuit_mismatch_rejected(self):
        prover = ZKProver("kyc-check.v1")
        with self.assertRaises(ZKInterfaceError):
            prover.prove(Statement("other.v1", {"a": 1}), {"w": 1})

    def test_non_statement_rejected(self):
        with self.assertRaises(TypeError):
            ZKProver("kyc-check.v1").prove("nope", {"w": 1})  # type: ignore[arg-type]

    def test_nan_witness_rejected(self):
        with self.assertRaises(ValueError):
            ZKProver("kyc-check.v1").prove(_stmt(), {"w": float("nan")})

    def test_non_mapping_witness_rejected(self):
        with self.assertRaises(TypeError):
            ZKProver("kyc-check.v1").prove(_stmt(), "w")  # type: ignore[arg-type]

    def test_witness_pin_statement_bound(self):
        s1 = _stmt()
        s2 = Statement("kyc-check.v1", {"age_over": 21})
        self.assertNotEqual(witness_pin(s1, {"w": 1}), witness_pin(s2, {"w": 1}))


class TestVerify(unittest.TestCase):
    def test_verify_happy_path(self):
        stmt = _stmt()
        proof = ZKProver("kyc-check.v1").prove(stmt, {"w": 1})
        self.assertTrue(verify(stmt, proof))

    def test_statement_substitution_fails(self):
        stmt = _stmt()
        proof = ZKProver("kyc-check.v1").prove(stmt, {"w": 1})
        other = Statement("kyc-check.v1", {"age_over": 21})
        self.assertFalse(verify(other, proof))

    def test_wrong_circuit_fails(self):
        stmt = _stmt()
        proof = ZKProver("kyc-check.v1").prove(stmt, {"w": 1})
        evil = Statement("evil.v1", {"age_over": 18})
        # rebind: same inputs, different circuit
        self.assertFalse(verify(evil, proof))

    def test_tampered_binding_fails(self):
        stmt = _stmt()
        proof = ZKProver("kyc-check.v1").prove(stmt, {"w": 1})
        import dataclasses

        tampered = dataclasses.replace(
            proof, proof_bytes=b"\x00" * 32 + proof.proof_bytes[32:]
        )
        self.assertFalse(verify(stmt, tampered))

    def test_non_proof_raises(self):
        with self.assertRaises(TypeError):
            verify(_stmt(), "nope")  # type: ignore[arg-type]

    def test_non_statement_raises(self):
        with self.assertRaises(TypeError):
            proof = ZKProver("kyc-check.v1").prove(_stmt(), {"w": 1})
            verify("nope", proof)  # type: ignore[arg-type]


class TestKeySeal(unittest.TestCase):
    def test_sealed_verify_with_key(self):
        prover = ZKProver("kyc-check.v1", verification_key=b"deploy-key")
        stmt = _stmt()
        proof = prover.prove(stmt, {"w": 1})
        self.assertTrue(verify(stmt, proof, verification_key=b"deploy-key"))

    def test_sealed_wrong_key_fails(self):
        prover = ZKProver("kyc-check.v1", verification_key=b"deploy-key")
        stmt = _stmt()
        proof = prover.prove(stmt, {"w": 1})
        self.assertFalse(verify(stmt, proof, verification_key=b"wrong-key"))

    def test_unsealed_with_key_required_fails(self):
        stmt = _stmt()
        proof = ZKProver("kyc-check.v1").prove(stmt, {"w": 1})
        self.assertFalse(verify(stmt, proof, verification_key=b"deploy-key"))

    def test_bad_key_type_rejected(self):
        with self.assertRaises(TypeError):
            ZKProver("c", verification_key="str")  # type: ignore[arg-type]

    def test_detailed_reasons(self):
        prover = ZKProver("kyc-check.v1", verification_key=b"k")
        stmt = _stmt()
        proof = prover.prove(stmt, {"w": 1})
        rep = verify_detailed(stmt, proof, verification_key=b"k")
        self.assertIsInstance(rep, StatementVerifyReport)
        self.assertTrue(rep.valid)
        for r in ("circuit-match", "inputs-match", "binding-ok",
                  "witness-pin-ok", "mac-ok"):
            self.assertIn(r, rep.reasons)

    def test_detailed_mac_mismatch(self):
        prover = ZKProver("kyc-check.v1", verification_key=b"k")
        stmt = _stmt()
        proof = prover.prove(stmt, {"w": 1})
        rep = verify_detailed(stmt, proof, verification_key=b"other")
        self.assertFalse(rep.valid)
        self.assertIn("mac-mismatch", rep.reasons)


class TestAuditEvent(unittest.TestCase):
    def test_shapes(self):
        for kind in ("proved", "verified", "verification-failed", "rejected"):
            ev = zk_audit_event(kind, "c.v1", 7)
            self.assertEqual(ev["schema"], "audit.ndjson/1")
            self.assertEqual(ev["kind"], f"zk-interface.{kind}")
            self.assertEqual(ev["version"], ZK_INTERFACE_VERSION)

    def test_witness_not_in_event(self):
        ev = zk_audit_event("proved", "c.v1", 1)
        self.assertNotIn("witness", ev)

    def test_bad_kind_rejected(self):
        with self.assertRaises(ValueError):
            zk_audit_event("nope", "c.v1", 1)

    def test_bad_seq_rejected(self):
        with self.assertRaises(ValueError):
            zk_audit_event("proved", "c.v1", True)
        with self.assertRaises(ValueError):
            zk_audit_event("proved", "c.v1", -1)


if __name__ == "__main__":
    unittest.main()
