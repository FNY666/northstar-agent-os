"""Tests for vector_commitment (Merkle-based vector commitment)."""

import unittest

from vector_commitment import (
    SCHEMA_PIN,
    VECTOR_COMMITMENT_VERSION,
    Commitment,
    OpeningProof,
    ProofStep,
    VectorCommitment,
    VectorCommitmentError,
    VerificationError,
    vector_commitment_audit_event,
    verify,
)


class TestPins(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(VECTOR_COMMITMENT_VERSION, "vector-commitment.v1")

    def test_schema_pin(self):
        self.assertEqual(SCHEMA_PIN, "northstar.vector-commitment.v1")


class TestCommit(unittest.TestCase):
    def test_commit_returns_commitment_record(self):
        vc = VectorCommitment([1, 2, 3])
        c = vc.commit()
        self.assertIsInstance(c, Commitment)
        self.assertEqual(c.size, 3)
        self.assertTrue(c.root.startswith("sha256:"))
        self.assertEqual(len(c.root), 71)

    def test_commit_deterministic(self):
        a = VectorCommitment(["x", "y"]).commit()
        b = VectorCommitment(["x", "y"]).commit()
        self.assertEqual(a.root, b.root)

    def test_commit_changes_when_value_changes(self):
        a = VectorCommitment(["x", "y"]).commit()
        b = VectorCommitment(["x", "z"]).commit()
        self.assertNotEqual(a.root, b.root)

    def test_commit_changes_when_order_changes(self):
        a = VectorCommitment(["x", "y"]).commit()
        b = VectorCommitment(["y", "x"]).commit()
        self.assertNotEqual(a.root, b.root)

    def test_rejects_empty_vector(self):
        with self.assertRaises(ValueError):
            VectorCommitment([])

    def test_rejects_non_sequence(self):
        with self.assertRaises(TypeError):
            VectorCommitment("abc")
        with self.assertRaises(TypeError):
            VectorCommitment({"a": 1})

    def test_rejects_non_canonicalizable_value(self):
        with self.assertRaises(TypeError):
            VectorCommitment([object()])

    def test_rejects_non_str_dict_key(self):
        with self.assertRaises(TypeError):
            VectorCommitment([{1: "x"}])

    def test_tuple_vector_accepted(self):
        vc = VectorCommitment((1, 2))
        self.assertEqual(vc.size, 2)


class TestOpen(unittest.TestCase):
    def test_open_returns_proof(self):
        vc = VectorCommitment([10, 20, 30])
        p = vc.open(1)
        self.assertIsInstance(p, OpeningProof)
        self.assertEqual(p.index, 1)
        self.assertEqual(p.size, 3)
        self.assertIsInstance(p.steps, tuple)
        self.assertTrue(all(isinstance(s, ProofStep) for s in p.steps))

    def test_open_rejects_negative(self):
        vc = VectorCommitment([1, 2])
        with self.assertRaises(ValueError):
            vc.open(-1)

    def test_open_rejects_out_of_range(self):
        vc = VectorCommitment([1, 2])
        with self.assertRaises(ValueError):
            vc.open(2)

    def test_open_rejects_bool(self):
        vc = VectorCommitment([1, 2])
        with self.assertRaises(TypeError):
            vc.open(True)

    def test_open_rejects_str(self):
        vc = VectorCommitment([1, 2])
        with self.assertRaises(TypeError):
            vc.open("0")


class TestVerify(unittest.TestCase):
    def setUp(self):
        self.values = ["alpha", "beta", "gamma", "delta", "epsilon"]
        self.vc = VectorCommitment(self.values)
        self.commitment = self.vc.commit()

    def test_verify_all_positions(self):
        for i, v in enumerate(self.values):
            proof = self.vc.open(i)
            self.assertTrue(verify(self.commitment, i, v, proof))

    def test_verify_single_element(self):
        vc = VectorCommitment(["only"])
        c = vc.commit()
        self.assertTrue(verify(c, 0, "only", vc.open(0)))

    def test_tampered_value_fails(self):
        proof = self.vc.open(1)
        self.assertFalse(verify(self.commitment, 1, "BETA", proof))

    def test_tampered_proof_step_fails(self):
        proof = self.vc.open(0)
        bad_steps = (ProofStep(sibling="sha256:" + "ab" * 32,
                               sibling_is_left=False),) + proof.steps[1:]
        bad = OpeningProof(index=proof.index, leaf=proof.leaf,
                           steps=bad_steps, size=proof.size)
        self.assertFalse(verify(self.commitment, 0, self.values[0], bad))

    def test_wrong_index_fails(self):
        # position binding: a proof for index 1 does not verify at index 0
        proof = self.vc.open(1)
        self.assertFalse(verify(self.commitment, 0, self.values[1], proof))

    def test_proof_from_other_vector_fails(self):
        other = VectorCommitment(["alpha", "BETA", "gamma", "delta",
                                  "epsilon"])
        self.assertFalse(verify(self.commitment, 1, "BETA",
                                other.open(1)))

    def test_size_mismatch_raises(self):
        other = VectorCommitment(["alpha", "beta"])
        with self.assertRaises(VerificationError):
            verify(self.commitment, 0, "alpha", other.open(0))

    def test_bad_types_raise(self):
        proof = self.vc.open(0)
        with self.assertRaises(TypeError):
            verify("not-a-commitment", 0, "alpha", proof)
        with self.assertRaises(TypeError):
            verify(self.commitment, 0, "alpha", "not-a-proof")
        with self.assertRaises(TypeError):
            verify(self.commitment, True, "alpha", proof)

    def test_non_canonicalizable_value_raises(self):
        proof = self.vc.open(0)
        with self.assertRaises(TypeError):
            verify(self.commitment, 0, object(), proof)


class TestOddSizes(unittest.TestCase):
    def test_odd_size_all_verify(self):
        for n in (1, 3, 5, 7):
            vc = VectorCommitment(list(range(n)))
            c = vc.commit()
            for i in range(n):
                self.assertTrue(verify(c, i, i, vc.open(i)),
                                f"n={n} index={i}")

    def test_proof_length_matches_tree_height(self):
        vc = VectorCommitment(list(range(5)))  # height 3
        self.assertEqual(len(vc.open(0).steps), 3)


class TestFrozenRecords(unittest.TestCase):
    def test_commitment_frozen(self):
        c = VectorCommitment([1]).commit()
        with self.assertRaises(Exception):
            c.root = "x"  # type: ignore

    def test_proof_frozen(self):
        p = VectorCommitment([1, 2]).open(0)
        with self.assertRaises(Exception):
            p.index = 9  # type: ignore

    def test_as_dict_shapes(self):
        c = VectorCommitment([1, 2]).commit()
        d = c.as_dict()
        self.assertEqual(d["schema"], SCHEMA_PIN)
        self.assertEqual(d["size"], 2)
        p = VectorCommitment([1, 2]).open(1)
        pd = p.as_dict()
        self.assertEqual(pd["index"], 1)
        self.assertEqual(pd["schema"], SCHEMA_PIN)


class TestAuditEvent(unittest.TestCase):
    def test_shapes(self):
        c = VectorCommitment(["a"]).commit()
        e = vector_commitment_audit_event("committed", 7, commitment=c)
        self.assertEqual(e["schema"], "audit.ndjson/1")
        self.assertEqual(e["kind"], "committed")
        self.assertEqual(e["audit_seq"], 7)
        self.assertEqual(e["root"], c.root)
        e2 = vector_commitment_audit_event("verified", 8, commitment=c,
                                           index=0, verified=True)
        self.assertTrue(e2["verified"])
        self.assertEqual(e2["index"], 0)

    def test_rejects_bad_kind(self):
        with self.assertRaises(ValueError):
            vector_commitment_audit_event("nope", 0)

    def test_rejects_bad_seq(self):
        with self.assertRaises(TypeError):
            vector_commitment_audit_event("committed", True)


if __name__ == "__main__":
    unittest.main()
