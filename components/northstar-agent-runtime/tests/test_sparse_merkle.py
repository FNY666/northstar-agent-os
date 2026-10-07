"""Tests for sparse_merkle.py — 256-bit sparse Merkle tree."""
import unittest

from sparse_merkle import (
    DEPTH,
    EMPTY_ROOT,
    SCHEMA_PIN,
    SPARSE_MERKLE_VERSION,
    SparseMerkleError,
    SparseMerkleProof,
    SparseMerkleTree,
    sparse_merkle_audit_event,
    verify_against,
    verify_proof,
)


class TestPins(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(SPARSE_MERKLE_VERSION, "sparse-merkle.v1")

    def test_schema_pin(self):
        self.assertEqual(SCHEMA_PIN, "northstar.sparse-merkle.v1")

    def test_depth(self):
        self.assertEqual(DEPTH, 256)


class TestEmptyTree(unittest.TestCase):
    def test_empty_root_is_default(self):
        tree = SparseMerkleTree()
        self.assertEqual(tree.root(), EMPTY_ROOT)

    def test_empty_tree_has_no_keys(self):
        tree = SparseMerkleTree()
        self.assertEqual(len(tree), 0)
        self.assertIsNone(tree.get("anything"))
        self.assertFalse(tree.contains("anything"))

    def test_non_inclusion_on_empty_tree(self):
        tree = SparseMerkleTree()
        proof = tree.proof("nobody")
        self.assertIsNone(proof.value)
        self.assertTrue(verify_proof(proof))


class TestUpdateGet(unittest.TestCase):
    def test_roundtrip_str(self):
        tree = SparseMerkleTree()
        tree.update("alice", "wallets:3")
        self.assertEqual(tree.get("alice"), b"wallets:3")

    def test_roundtrip_bytes(self):
        tree = SparseMerkleTree()
        tree.update(b"\x00\x01", b"\xff")
        self.assertEqual(tree.get(b"\x00\x01"), b"\xff")

    def test_str_and_bytes_keys_agree(self):
        tree = SparseMerkleTree()
        tree.update("k", "v")
        self.assertEqual(tree.get(b"k"), b"v")
        self.assertTrue(tree.contains(b"k"))

    def test_overwrite(self):
        tree = SparseMerkleTree()
        tree.update("k", "v1")
        tree.update("k", "v2")
        self.assertEqual(tree.get("k"), b"v2")
        self.assertEqual(len(tree), 1)

    def test_root_changes_on_update(self):
        tree = SparseMerkleTree()
        r0 = tree.root()
        tree.update("k", "v")
        self.assertNotEqual(tree.root(), r0)

    def test_empty_value_is_present_not_absent(self):
        tree = SparseMerkleTree()
        tree.update("k", b"")
        self.assertEqual(tree.get("k"), b"")
        self.assertTrue(tree.contains("k"))
        proof = tree.proof("k")
        self.assertEqual(proof.value, b"")
        self.assertTrue(verify_proof(proof))


class TestValidation(unittest.TestCase):
    def test_key_type_rejected(self):
        tree = SparseMerkleTree()
        for bad in (123, None, ["k"], {"k": 1}, 4.5):
            with self.assertRaises(TypeError):
                tree.update(bad, "v")
            with self.assertRaises(TypeError):
                tree.get(bad)
            with self.assertRaises(TypeError):
                tree.proof(bad)

    def test_empty_key_rejected(self):
        tree = SparseMerkleTree()
        for bad in ("", b""):
            with self.assertRaises(ValueError):
                tree.update(bad, "v")

    def test_value_type_rejected(self):
        tree = SparseMerkleTree()
        for bad in (123, None, ["v"], {"v": 1}):
            with self.assertRaises(TypeError):
                tree.update("k", bad)


class TestDelete(unittest.TestCase):
    def test_delete_present(self):
        tree = SparseMerkleTree()
        tree.update("k", "v")
        self.assertTrue(tree.delete("k"))
        self.assertIsNone(tree.get("k"))
        self.assertEqual(len(tree), 0)

    def test_delete_missing_returns_false(self):
        tree = SparseMerkleTree()
        self.assertFalse(tree.delete("nope"))

    def test_delete_restores_empty_root(self):
        tree = SparseMerkleTree()
        tree.update("k", "v")
        tree.delete("k")
        self.assertEqual(tree.root(), EMPTY_ROOT)

    def test_proof_after_delete_is_non_inclusion(self):
        tree = SparseMerkleTree()
        tree.update("k", "v")
        tree.delete("k")
        proof = tree.proof("k")
        self.assertIsNone(proof.value)
        self.assertTrue(verify_proof(proof))


class TestProofs(unittest.TestCase):
    def test_inclusion_proof_verifies(self):
        tree = SparseMerkleTree()
        for i in range(10):
            tree.update(f"key-{i}", f"value-{i}")
        proof = tree.proof("key-4")
        self.assertEqual(proof.value, b"value-4")
        self.assertTrue(verify_proof(proof))

    def test_sibling_count(self):
        tree = SparseMerkleTree()
        tree.update("k", "v")
        self.assertEqual(len(tree.proof("k").siblings), 256)

    def test_proof_root_matches_tree(self):
        tree = SparseMerkleTree()
        tree.update("k", "v")
        self.assertEqual(tree.proof("k").root, tree.root())

    def test_tampered_value_fails(self):
        tree = SparseMerkleTree()
        tree.update("k", "v")
        proof = tree.proof("k")
        bad = SparseMerkleProof(
            key=proof.key, path=proof.path, value=b"evil",
            siblings=proof.siblings, root=proof.root)
        self.assertFalse(verify_proof(bad))

    def test_tampered_sibling_fails(self):
        tree = SparseMerkleTree()
        tree.update("k", "v")
        proof = tree.proof("k")
        siblings = list(proof.siblings)
        siblings[0] = b"\x00" * 32
        bad = SparseMerkleProof(
            key=proof.key, path=proof.path, value=proof.value,
            siblings=tuple(siblings), root=proof.root)
        self.assertFalse(verify_proof(bad))

    def test_tampered_root_fails(self):
        tree = SparseMerkleTree()
        tree.update("k", "v")
        proof = tree.proof("k")
        bad = SparseMerkleProof(
            key=proof.key, path=proof.path, value=proof.value,
            siblings=proof.siblings, root=b"\x11" * 32)
        self.assertFalse(verify_proof(bad))

    def test_non_proof_rejected(self):
        with self.assertRaises(TypeError):
            verify_proof({"not": "a proof"})

    def test_verify_against_trusted_root(self):
        tree = SparseMerkleTree()
        tree.update("k", "v")
        root = tree.root()
        self.assertTrue(verify_against(root, tree.proof("k")))
        self.assertFalse(verify_against(b"\x22" * 32, tree.proof("k")))

    def test_verify_against_bad_root_type(self):
        tree = SparseMerkleTree()
        tree.update("k", "v")
        with self.assertRaises(TypeError):
            verify_against("not-bytes", tree.proof("k"))

    def test_proof_as_dict(self):
        tree = SparseMerkleTree()
        tree.update("k", "v")
        d = tree.proof("k").as_dict()
        self.assertEqual(d["schema"], SCHEMA_PIN)
        self.assertEqual(d["root_hex"], tree.root_hex())
        self.assertTrue(d["inclusion"])
        self.assertEqual(len(d["siblings_hex"]), 256)


class TestDeterminism(unittest.TestCase):
    def test_same_updates_same_root(self):
        t1, t2 = SparseMerkleTree(), SparseMerkleTree()
        for i in range(20):
            t1.update(f"k{i}", f"v{i}")
            t2.update(f"k{i}", f"v{i}")
        self.assertEqual(t1.root(), t2.root())

    def test_update_order_independent(self):
        t1, t2 = SparseMerkleTree(), SparseMerkleTree()
        keys = [f"k{i}" for i in range(20)]
        for k in keys:
            t1.update(k, "v")
        for k in reversed(keys):
            t2.update(k, "v")
        self.assertEqual(t1.root(), t2.root())

    def test_proofs_stable_across_trees(self):
        t1, t2 = SparseMerkleTree(), SparseMerkleTree()
        t1.update("a", "1")
        t1.update("b", "2")
        t2.update("b", "2")
        t2.update("a", "1")
        p1, p2 = t1.proof("a"), t2.proof("a")
        self.assertEqual(p1.as_dict(), p2.as_dict())


class TestAuditEvent(unittest.TestCase):
    def test_shapes(self):
        tree = SparseMerkleTree()
        tree.update("k", "v")
        for kind in ("updated", "deleted", "proof-generated",
                     "proof-verified"):
            e = sparse_merkle_audit_event(kind, 7, key="k",
                                          root=tree.root(),
                                          verified=True)
            self.assertEqual(e["schema"], "audit.ndjson/1")
            self.assertEqual(e["module"], SCHEMA_PIN)
            self.assertEqual(e["kind"], kind)
            self.assertEqual(e["audit_seq"], 7)
            self.assertEqual(len(e["key_sha256"]), 64)
            self.assertEqual(e["root_hex"], tree.root_hex())

    def test_bad_kind_rejected(self):
        with self.assertRaises(ValueError):
            sparse_merkle_audit_event("nope", 1)

    def test_bad_seq_rejected(self):
        with self.assertRaises(TypeError):
            sparse_merkle_audit_event("updated", True)
        with self.assertRaises(ValueError):
            sparse_merkle_audit_event("updated", -1)

    def test_bad_root_rejected(self):
        with self.assertRaises(TypeError):
            sparse_merkle_audit_event("updated", 1, root=b"short")


class TestMain(unittest.TestCase):
    def test_main_runs(self):
        import sparse_merkle
        sparse_merkle.main()


if __name__ == "__main__":
    unittest.main()
