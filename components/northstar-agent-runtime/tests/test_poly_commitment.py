"""Tests for poly_commitment (simulated KZG-style interface)."""

import dataclasses
import unittest

from poly_commitment import (
    SCHEMA_PIN,
    POLY_COMMITMENT_VERSION,
    Commitment,
    EvalProof,
    PolyCommitment,
    PolyCommitmentError,
    poly_commitment_audit_event,
    verify,
)


def _p(coeffs):
    return PolyCommitment(coeffs)


class TestPins(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(POLY_COMMITMENT_VERSION, "poly-commitment.v1")

    def test_schema_pin(self):
        self.assertEqual(SCHEMA_PIN, "northstar.poly-commitment.v1")


class TestConstruction(unittest.TestCase):
    def test_coeffs_stored_canonical(self):
        self.assertEqual(_p([1, 2, 3]).coeffs, (1, 2, 3))

    def test_trailing_zeros_stripped(self):
        self.assertEqual(_p([1, 2, 0, 0]).coeffs, (1, 2))

    def test_trailing_zeros_commit_identically(self):
        self.assertEqual(
            _p([1, 2, 0, 0]).commit().digest, _p([1, 2]).commit().digest
        )

    def test_zero_polynomial_keeps_one_coeff(self):
        self.assertEqual(_p([0, 0]).coeffs, (0,))

    def test_degree(self):
        self.assertEqual(_p([5]).degree, 0)
        self.assertEqual(_p([1, 2, 3]).degree, 2)

    def test_empty_coeffs_rejected(self):
        with self.assertRaises(PolyCommitmentError):
            _p([])

    def test_bool_coeff_rejected(self):
        with self.assertRaises(PolyCommitmentError):
            _p([1, True])

    def test_non_int_coeff_rejected(self):
        with self.assertRaises(PolyCommitmentError):
            _p([1, 2.5])

    def test_non_sequence_rejected(self):
        with self.assertRaises(PolyCommitmentError):
            _p("123")


class TestCommit(unittest.TestCase):
    def test_deterministic(self):
        self.assertEqual(_p([1, 2, 3]).commit().digest, _p([1, 2, 3]).commit().digest)

    def test_distinct_polys_distinct_digests(self):
        self.assertNotEqual(_p([1, 2, 3]).commit().digest, _p([1, 2, 4]).commit().digest)

    def test_digest_shape(self):
        d = _p([1]).commit().digest
        self.assertTrue(d.startswith("sha256:"))
        self.assertEqual(len(d), len("sha256:") + 64)

    def test_commitment_metadata(self):
        c = _p([1, 2, 3]).commit()
        self.assertEqual(c.degree, 2)
        self.assertEqual(c.n_coeffs, 3)

    def test_big_int_coeffs_deterministic_and_distinct(self):
        # >2^53 coefficients must not collide via float-serialized JSON.
        a = _p([2**70, -(2**80)]).commit().digest
        b = _p([2**70, -(2**80)]).commit().digest
        c = _p([2**70, -(2**80) + 1]).commit().digest
        self.assertEqual(a, b)
        self.assertNotEqual(a, c)

    def test_commitment_frozen(self):
        c = _p([1]).commit()
        with self.assertRaises(dataclasses.FrozenInstanceError):
            c.degree = 9  # type: ignore[misc]

    def test_commitment_bad_digest_rejected(self):
        with self.assertRaises(PolyCommitmentError):
            Commitment(digest="nope", degree=0, n_coeffs=1)

    def test_commitment_metadata_consistency(self):
        with self.assertRaises(PolyCommitmentError):
            Commitment(digest="sha256:" + "a" * 64, degree=2, n_coeffs=2)

    def test_commitment_as_dict(self):
        d = _p([1, 2]).commit().as_dict()
        self.assertEqual(d["schema"], SCHEMA_PIN)
        self.assertEqual(d["degree"], 1)
        self.assertIn("digest", d)


class TestEvaluate(unittest.TestCase):
    def test_horner(self):
        # 1 + 2x + 3x^2 at x=2 -> 17
        self.assertEqual(_p([1, 2, 3]).evaluate(2), 17)

    def test_negative_point_and_coeffs(self):
        # -5 + 4x^2 at x=-2 -> 11
        self.assertEqual(_p([-5, 0, 4]).evaluate(-2), 11)

    def test_bool_point_rejected(self):
        with self.assertRaises(PolyCommitmentError):
            _p([1, 2]).evaluate(True)

    def test_str_point_rejected(self):
        with self.assertRaises(PolyCommitmentError):
            _p([1, 2]).evaluate("2")


class TestEvalProof(unittest.TestCase):
    def test_value_matches_evaluate(self):
        pc = _p([1, 2, 3])
        proof = pc.eval_proof(2)
        self.assertEqual(proof.value, 17)
        self.assertEqual(proof.point, 2)

    def test_quotient_shape(self):
        # q(x) = (p(x) - 17)/(x - 2) = 8 + 3x
        proof = _p([1, 2, 3]).eval_proof(2)
        self.assertEqual(proof.quotient_coeffs, (8, 3))

    def test_constant_poly_empty_quotient(self):
        proof = _p([7]).eval_proof(-3)
        self.assertEqual(proof.quotient_coeffs, ())
        self.assertEqual(proof.value, 7)

    def test_proof_frozen(self):
        proof = _p([1]).eval_proof(0)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            proof.value = 9  # type: ignore[misc]

    def test_proof_as_dict_schema(self):
        d = _p([1, 2]).eval_proof(3).as_dict()
        self.assertEqual(d["schema"], SCHEMA_PIN)
        self.assertEqual(d["point"], "3")  # hex-encoded, JCS-safe

    def test_proof_names_commitment(self):
        pc = _p([1, 2, 3])
        proof = pc.eval_proof(2)
        self.assertEqual(proof.commitment_digest, pc.commit().digest)


class TestVerify(unittest.TestCase):
    def test_happy_path(self):
        pc = _p([1, 2, 3])
        self.assertTrue(verify(pc.commit(), 2, 17, pc.eval_proof(2)))

    def test_wrong_value_fails(self):
        pc = _p([1, 2, 3])
        self.assertFalse(verify(pc.commit(), 2, 18, pc.eval_proof(2)))

    def test_tampered_quotient_fails(self):
        pc = _p([1, 2, 3])
        proof = pc.eval_proof(2)
        bad = EvalProof(
            commitment_digest=proof.commitment_digest,
            point=proof.point,
            value=proof.value,
            quotient_coeffs=(9, 3),
            coeffs=proof.coeffs,
        )
        self.assertFalse(verify(pc.commit(), 2, 17, bad))

    def test_tampered_coeffs_fail_digest(self):
        pc = _p([1, 2, 3])
        proof = pc.eval_proof(2)
        bad = EvalProof(
            commitment_digest=proof.commitment_digest,
            point=proof.point,
            value=proof.value,
            quotient_coeffs=proof.quotient_coeffs,
            coeffs=(1, 2, 4),
        )
        self.assertFalse(verify(pc.commit(), 2, 17, bad))

    def test_wrong_commitment_fails(self):
        pc = _p([1, 2, 3])
        other = _p([1, 2, 4])
        self.assertFalse(verify(other.commit(), 2, 17, pc.eval_proof(2)))

    def test_proof_point_mismatch_fails(self):
        pc = _p([1, 2, 3])
        self.assertFalse(verify(pc.commit(), 5, 17, pc.eval_proof(2)))

    def test_zero_polynomial(self):
        pc = _p([0])
        self.assertTrue(verify(pc.commit(), 5, 0, pc.eval_proof(5)))

    def test_negative_point(self):
        pc = _p([-5, 0, 4])
        self.assertTrue(verify(pc.commit(), -2, 11, pc.eval_proof(-2)))

    def test_quotient_identity_checked(self):
        # Independent recomputation: (x - z)*q(x) + y must equal p(x).
        pc = _p([3, -1, 2, 5])
        z = 4
        proof = pc.eval_proof(z)
        q = proof.quotient_coeffs
        y = proof.value
        m = len(q)
        r = [0] * (m + 1)
        r[0] = y - z * q[0]
        for k in range(1, m):
            r[k] = q[k - 1] - z * q[k]
        r[m] = q[m - 1]
        self.assertEqual(tuple(r), pc.coeffs)

    def test_bad_types_raise(self):
        pc = _p([1, 2])
        proof = pc.eval_proof(1)
        with self.assertRaises(PolyCommitmentError):
            verify("nope", 1, 3, proof)  # type: ignore[arg-type]
        with self.assertRaises(PolyCommitmentError):
            verify(pc.commit(), 1, 3, "nope")  # type: ignore[arg-type]
        with self.assertRaises(PolyCommitmentError):
            verify(pc.commit(), True, 3, proof)
        with self.assertRaises(PolyCommitmentError):
            verify(pc.commit(), 1, 3.5, proof)


class TestAuditEvent(unittest.TestCase):
    def test_shapes(self):
        for kind in ("committed", "proof-generated", "verified", "verification-failed"):
            ev = poly_commitment_audit_event(kind, {"digest": "sha256:" + "a" * 64}, 7)
            self.assertEqual(ev["schema"], SCHEMA_PIN)
            self.assertEqual(ev["kind"], f"poly-commitment.{kind}")
            self.assertEqual(ev["audit_seq"], 7)

    def test_bad_kind_rejected(self):
        with self.assertRaises(PolyCommitmentError):
            poly_commitment_audit_event("nope", {}, 1)

    def test_bad_seq_rejected(self):
        with self.assertRaises(PolyCommitmentError):
            poly_commitment_audit_event("committed", {}, -1)

    def test_non_mapping_rejected(self):
        with self.assertRaises(PolyCommitmentError):
            poly_commitment_audit_event("committed", [], 1)  # type: ignore[arg-type]


class TestMain(unittest.TestCase):
    def test_main_runs(self):
        import poly_commitment as m

        m.main()  # asserts internally; raises on failure


if __name__ == "__main__":
    unittest.main()
