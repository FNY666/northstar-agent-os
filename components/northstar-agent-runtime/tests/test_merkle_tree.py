"""Tests for merkle_tree.py (targeted)."""

import unittest

from merkle_tree import (
    MERKLETREE_VERSION,
    SCHEMA_PIN,
    MerkleProof,
    MerkleTree,
    merkle_tree_audit_event,
    verify,
)


def _leaves(n):
    return [f"leaf-{i}".encode() for i in range(n)]


class TestPins(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(MERKLETREE_VERSION, "merkle-tree.v1")

    def test_schema_pin(self):
        self.assertEqual(SCHEMA_PIN, "northstar.merkle-tree.v1")


class TestConstruction(unittest.TestCase):
    def test_empty_leaves_rejected(self):
        with self.assertRaises(ValueError):
            MerkleTree([])

    def test_non_list_rejected(self):
        with self.assertRaises(TypeError):
            MerkleTree("not-a-list")

    def test_non_bytes_leaf_rejected(self):
        with self.assertRaises(TypeError):
            MerkleTree([b"ok", "not-bytes"])

    def test_tuple_leaves_accepted(self):
        t = MerkleTree((b"a", b"b"))
        self.assertEqual(t.leaf_count, 2)

    def test_leaf_count(self):
        self.assertEqual(MerkleTree(_leaves(5)).leaf_count, 5)


class TestRoot(unittest.TestCase):
    def test_root_is_pinned(self):
        self.assertTrue(MerkleTree(_leaves(4)).root().startswith("sha256:"))

    def test_root_deterministic(self):
        a = MerkleTree(_leaves(8)).root()
        b = MerkleTree(_leaves(8)).root()
        self.assertEqual(a, b)

    def test_root_order_sensitive(self):
        fwd = MerkleTree(_leaves(4)).root()
        rev = MerkleTree(list(reversed(_leaves(4)))).root()
        self.assertNotEqual(fwd, rev)

    def test_root_changes_on_leaf_change(self):
        a = MerkleTree(_leaves(4)).root()
        other = _leaves(4)
        other[2] = b"changed"
        b = MerkleTree(other).root()
        self.assertNotEqual(a, b)

    def test_single_leaf_root_is_leaf_hash(self):
        t = MerkleTree([b"solo"])
        self.assertEqual(t.root(), t.leaf_digest(0))

    def test_leaf_digest_out_of_range(self):
        t = MerkleTree(_leaves(3))
        with self.assertRaises(ValueError):
            t.leaf_digest(3)
        with self.assertRaises(ValueError):
            t.leaf_digest(-1)

    def test_leaf_digest_bad_type(self):
        t = MerkleTree(_leaves(3))
        with self.assertRaises(TypeError):
            t.leaf_digest(True)


class TestProof(unittest.TestCase):
    def test_proof_shape(self):
        t = MerkleTree(_leaves(4))
        p = t.proof(1)
        self.assertIsInstance(p, MerkleProof)
        self.assertEqual(p.index, 1)
        self.assertEqual(p.leaf_count, 4)
        self.assertEqual(p.root, t.root())
        self.assertTrue(p.leaf_digest.startswith("sha256:"))
        self.assertIsInstance(p.siblings, tuple)
        self.assertEqual(p.schema, SCHEMA_PIN)

    def test_proof_out_of_range(self):
        t = MerkleTree(_leaves(4))
        with self.assertRaises(ValueError):
            t.proof(4)
        with self.assertRaises(ValueError):
            t.proof(-1)

    def test_proof_bad_type(self):
        t = MerkleTree(_leaves(4))
        with self.assertRaises(TypeError):
            t.proof(True)
        with self.assertRaises(TypeError):
            t.proof("1")

    def test_single_leaf_empty_siblings(self):
        t = MerkleTree([b"only"])
        self.assertEqual(t.proof(0).siblings, ())

    def test_proof_sibling_depth(self):
        # 8 leaves -> 3 levels of siblings.
        t = MerkleTree(_leaves(8))
        self.assertEqual(len(t.proof(3).siblings), 3)

    def test_proof_frozen(self):
        t = MerkleTree(_leaves(4))
        p = t.proof(0)
        with self.assertRaises(Exception):
            p.index = 9

    def test_proof_as_dict(self):
        t = MerkleTree(_leaves(4))
        d = t.proof(2).as_dict()
        self.assertEqual(d["index"], 2)
        self.assertEqual(d["leaf_count"], 4)
        self.assertEqual(d["schema"], SCHEMA_PIN)
        self.assertIsInstance(d["siblings"], list)


class TestVerify(unittest.TestCase):
    def test_verify_all_leaves_even(self):
        leaves = _leaves(8)
        t = MerkleTree(leaves)
        root = t.root()
        for i in range(8):
            self.assertTrue(verify(t.proof(i), leaves[i], root), f"index {i}")

    def test_verify_all_leaves_odd(self):
        leaves = _leaves(7)
        t = MerkleTree(leaves)
        root = t.root()
        for i in range(7):
            self.assertTrue(verify(t.proof(i), leaves[i], root), f"index {i}")

    def test_verify_tampered_leaf(self):
        t = MerkleTree(_leaves(4))
        self.assertFalse(verify(t.proof(0), b"tampered", t.root()))

    def test_verify_wrong_root(self):
        leaves = _leaves(4)
        t = MerkleTree(leaves)
        other = MerkleTree([b"x", b"y", b"z", b"w"]).root()
        self.assertFalse(verify(t.proof(1), leaves[1], other))

    def test_verify_wrong_leaf_same_tree(self):
        leaves = _leaves(4)
        t = MerkleTree(leaves)
        # Proof for index 0 replayed with leaf 1's bytes must fail.
        self.assertFalse(verify(t.proof(0), leaves[1], t.root()))

    def test_verify_tampered_sibling(self):
        t = MerkleTree(_leaves(4))
        p = t.proof(2)
        bad_sibs = ("sha256:" + "ff" * 32,) + p.siblings[1:]
        bad = MerkleProof(
            index=p.index,
            leaf_count=p.leaf_count,
            leaf_digest=p.leaf_digest,
            siblings=bad_sibs,
            root=p.root,
        )
        self.assertFalse(verify(bad, _leaves(4)[2], t.root()))

    def test_verify_bad_types_return_false(self):
        t = MerkleTree(_leaves(4))
        p = t.proof(0)
        root = t.root()
        self.assertFalse(verify("not-a-proof", b"leaf-0", root))
        self.assertFalse(verify(p, "not-bytes", root))
        self.assertFalse(verify(p, b"leaf-0", "not-a-pin"))
        self.assertFalse(verify(None, None, None))


class TestAuditEvent(unittest.TestCase):
    def test_audit_event_shape(self):
        root = MerkleTree(_leaves(3)).root()
        evt = merkle_tree_audit_event(root, 3, audit_seq=5)
        self.assertEqual(evt["event"], "merkle-root-anchored")
        self.assertEqual(evt["root"], root)
        self.assertEqual(evt["leaf_count"], 3)
        self.assertEqual(evt["audit_seq"], 5)
        self.assertEqual(evt["schema"], SCHEMA_PIN)

    def test_audit_event_bad_root(self):
        with self.assertRaises(TypeError):
            merkle_tree_audit_event("no-pin", 3, audit_seq=0)

    def test_audit_event_bad_count(self):
        root = MerkleTree(_leaves(3)).root()
        with self.assertRaises(ValueError):
            merkle_tree_audit_event(root, 0, audit_seq=0)
        with self.assertRaises(TypeError):
            merkle_tree_audit_event(root, True, audit_seq=0)

    def test_audit_event_bad_seq(self):
        root = MerkleTree(_leaves(3)).root()
        with self.assertRaises(ValueError):
            merkle_tree_audit_event(root, 3, audit_seq=-1)
        with self.assertRaises(TypeError):
            merkle_tree_audit_event(root, 3, audit_seq=False)


class TestMain(unittest.TestCase):
    def test_main(self):
        import merkle_tree as mt

        self.assertIsNone(mt.main())


if __name__ == "__main__":
    unittest.main()
