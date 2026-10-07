"""Tests for verkle_tree: vector commitments, trie, inclusion/non-inclusion proofs."""

import ast
import dataclasses
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from verkle_tree import (
    EMPTY_PIN,
    SCHEMA_PIN,
    VERKLE_TREE_VERSION,
    KeyPathCollisionError,
    ProofLevel,
    VerkleProof,
    VerkleTree,
    VerkleTreeError,
    vc_commit,
    vc_open,
    vc_verify,
    verkle_audit_event,
    verify_proof,
)


def _small_tree():
    return VerkleTree(branching=16, depth=8)


class TestPins(unittest.TestCase):
    def test_version_and_schema_pins(self):
        self.assertEqual(VERKLE_TREE_VERSION, "verkle-tree.v1")
        self.assertEqual(SCHEMA_PIN, "northstar.verkle-tree.v1")
        self.assertTrue(EMPTY_PIN.startswith("sha256:"))
        self.assertEqual(len(EMPTY_PIN), 71)

    def test_empty_tree_root(self):
        tree = _small_tree()
        root = tree.root()
        # well-formed pin, deterministic, and not the bare empty slot
        self.assertTrue(root.startswith("sha256:") and len(root) == 71)
        self.assertNotEqual(root, EMPTY_PIN)
        self.assertEqual(root, VerkleTree(branching=16, depth=8).root())
        self.assertEqual(len(tree), 0)


class TestConstructor(unittest.TestCase):
    def test_defaults(self):
        tree = VerkleTree()
        self.assertEqual(tree.branching, 16)
        self.assertEqual(tree.depth, 64)

    def test_bad_branching(self):
        for bad in (1, 257, 0, -4):
            with self.assertRaises(ValueError):
                VerkleTree(branching=bad)
        for bad in (True, False, "16", 16.0, None):
            with self.assertRaises(TypeError):
                VerkleTree(branching=bad)

    def test_bad_depth(self):
        for bad in (0, 65, -1):
            with self.assertRaises(ValueError):
                VerkleTree(depth=bad)
        for bad in (True, "8", 8.0, None):
            with self.assertRaises(TypeError):
                VerkleTree(depth=bad)


class TestPutGet(unittest.TestCase):
    def test_roundtrip_str_key(self):
        tree = _small_tree()
        tree.put("alice", {"balance": 100})
        self.assertEqual(tree.get("alice"), {"balance": 100})

    def test_roundtrip_bytes_key(self):
        tree = _small_tree()
        tree.put(b"\x00\x01bob", [1, 2, 3])
        self.assertEqual(tree.get(b"\x00\x01bob"), [1, 2, 3])

    def test_get_missing_returns_none(self):
        tree = _small_tree()
        tree.put("alice", 1)
        self.assertIsNone(tree.get("nobody"))

    def test_put_overwrites_same_key(self):
        tree = _small_tree()
        tree.put("k", 1)
        tree.put("k", 2)
        self.assertEqual(tree.get("k"), 2)
        self.assertEqual(len(tree), 1)

    def test_len_tracks_inserts(self):
        tree = _small_tree()
        for i in range(10):
            tree.put(f"key-{i}", i)
        self.assertEqual(len(tree), 10)

    def test_bad_keys(self):
        tree = _small_tree()
        for bad in ("", b""):
            with self.assertRaises(ValueError):
                tree.put(bad, 1)
        for bad in (None, 123, True, ["k"]):
            with self.assertRaises(TypeError):
                tree.put(bad, 1)
            with self.assertRaises(TypeError):
                tree.get(bad)

    def test_bad_values(self):
        tree = _small_tree()
        with self.assertRaises(TypeError):
            tree.put("k", object())
        with self.assertRaises(TypeError):
            tree.put("k", ("tuple", "not", "allowed"))
        with self.assertRaises(ValueError):
            tree.put("k", float("nan"))
        with self.assertRaises(ValueError):
            tree.put("k", float("inf"))
        with self.assertRaises(TypeError):
            tree.put("k", {1: "non-str-key"})
        # JSON scalar values are fine, including bool
        for ok in (None, True, 0, 1.5, "s", [], {}, {"a": [1, {"b": None}]}):
            tree.put("k", ok)
            self.assertEqual(tree.get("k"), ok)

    def test_root_changes_and_deterministic(self):
        a = _small_tree()
        b = _small_tree()
        a.put("x", 1)
        a.put("y", 2)
        b.put("y", 2)
        b.put("x", 1)
        self.assertEqual(a.root(), b.root())  # order-independent
        b.put("z", 3)
        self.assertNotEqual(a.root(), b.root())

    def test_branching_256(self):
        tree = VerkleTree(branching=256, depth=4)
        tree.put("k", "v")
        self.assertEqual(tree.get("k"), "v")
        self.assertTrue(tree.proof("k").verify("k", "v"))


class TestVectorCommitment(unittest.TestCase):
    def test_commit_deterministic_and_order_sensitive(self):
        pins = [EMPTY_PIN, vc_commit([EMPTY_PIN] * 2)]
        self.assertEqual(vc_commit(pins), vc_commit(list(pins)))
        self.assertNotEqual(vc_commit(pins), vc_commit(pins[::-1]))

    def test_commit_rejects_bad_pins(self):
        with self.assertRaises(ValueError):
            vc_commit([])
        with self.assertRaises(ValueError):
            vc_commit(["not-a-pin"])

    def test_open_verify_roundtrip(self):
        pins = [EMPTY_PIN] * 16
        c = vc_commit(pins)
        opening = vc_open(c, 3, EMPTY_PIN)
        self.assertTrue(vc_verify(c, 3, EMPTY_PIN, opening))

    def test_verify_rejects_mismatch(self):
        c = vc_commit([EMPTY_PIN] * 16)
        opening = vc_open(c, 3, EMPTY_PIN)
        self.assertFalse(vc_verify(c, 4, EMPTY_PIN, opening))  # wrong index
        self.assertFalse(vc_verify(c, 3, vc_commit([EMPTY_PIN] * 2),
                                  opening))  # wrong pin
        self.assertFalse(vc_verify(c, 3, EMPTY_PIN, "sha256:" + "ff" * 64))
        self.assertFalse(vc_verify("garbage", 3, EMPTY_PIN, opening))

    def test_open_rejects_bad_inputs(self):
        c = vc_commit([EMPTY_PIN] * 4)
        with self.assertRaises(ValueError):
            vc_open("bad", 0, EMPTY_PIN)
        with self.assertRaises(TypeError):
            vc_open(c, True, EMPTY_PIN)
        with self.assertRaises(ValueError):
            vc_open(c, -1, EMPTY_PIN)


class TestProofs(unittest.TestCase):
    def test_inclusion_proof_verifies(self):
        tree = _small_tree()
        tree.put("alice", {"balance": 100})
        proof = tree.proof("alice")
        self.assertTrue(proof.present)
        self.assertEqual(len(proof.levels), 8)
        self.assertEqual(proof.root, tree.root())
        self.assertTrue(proof.verify("alice", {"balance": 100}))
        self.assertTrue(verify_proof(proof, "alice", {"balance": 100}))

    def test_proof_fails_wrong_value(self):
        tree = _small_tree()
        tree.put("alice", 1)
        proof = tree.proof("alice")
        self.assertFalse(proof.verify("alice", 2))
        self.assertFalse(proof.verify("alice"))  # value required

    def test_proof_fails_wrong_key(self):
        tree = _small_tree()
        tree.put("alice", 1)
        proof = tree.proof("alice")
        self.assertFalse(proof.verify("bob", 1))

    def test_proof_fails_tampered_root(self):
        tree = _small_tree()
        tree.put("alice", 1)
        proof = tree.proof("alice")
        tampered = dataclasses.replace(proof, root="sha256:" + "ab" * 32)
        self.assertFalse(tampered.verify("alice", 1))

    def test_proof_fails_tampered_opening(self):
        tree = _small_tree()
        tree.put("alice", 1)
        proof = tree.proof("alice")
        bad_level = dataclasses.replace(proof.levels[-1],
                                        opening="sha256:" + "ff" * 32)
        tampered = dataclasses.replace(
            proof, levels=proof.levels[:-1] + (bad_level,))
        self.assertFalse(tampered.verify("alice", 1))

    def test_proof_fails_reordered_levels(self):
        tree = _small_tree()
        tree.put("alice", 1)
        proof = tree.proof("alice")
        flipped = dataclasses.replace(proof,
                                      levels=tuple(reversed(proof.levels)))
        self.assertFalse(flipped.verify("alice", 1))

    def test_non_inclusion_proof_verifies(self):
        tree = _small_tree()
        tree.put("alice", 1)
        proof = tree.proof("carol")
        self.assertFalse(proof.present)
        self.assertIsNone(proof.value_digest)
        self.assertTrue(proof.verify("carol"))
        self.assertTrue(verify_proof(proof, "carol"))

    def test_non_inclusion_proof_rejects_value(self):
        tree = _small_tree()
        proof = tree.proof("carol")
        self.assertFalse(proof.verify("carol", 1))

    def test_non_inclusion_on_empty_tree(self):
        tree = _small_tree()
        proof = tree.proof("nobody")
        self.assertFalse(proof.present)
        self.assertTrue(proof.verify("nobody"))
        self.assertEqual(proof.root, tree.root())

    def test_proof_after_overwrite(self):
        tree = _small_tree()
        tree.put("k", 1)
        old = tree.proof("k")
        tree.put("k", 2)
        new = tree.proof("k")
        self.assertTrue(new.verify("k", 2))
        self.assertFalse(old.verify("k", 2))  # stale proof, new root
        self.assertNotEqual(old.root, new.root)

    def test_proof_key_mismatch(self):
        tree = _small_tree()
        tree.put("alice", 1)
        proof = tree.proof("alice")
        with self.assertRaises(TypeError):
            verify_proof("not-a-proof", "alice", 1)

    def test_proof_records_frozen(self):
        tree = _small_tree()
        tree.put("a", 1)
        proof = tree.proof("a")
        with self.assertRaises(dataclasses.FrozenInstanceError):
            proof.present = True  # type: ignore[misc]
        with self.assertRaises(dataclasses.FrozenInstanceError):
            proof.levels[0].index = 0  # type: ignore[misc]

    def test_proof_as_dict_shape(self):
        tree = _small_tree()
        tree.put("a", 1)
        d = tree.proof("a").as_dict()
        self.assertEqual(d["schema"], SCHEMA_PIN)
        self.assertEqual(d["version"], VERKLE_TREE_VERSION)
        self.assertTrue(d["present"])
        self.assertEqual(len(d["levels"]), 8)
        self.assertIn("key_hex", d)

    def test_key_path_collision_is_fail_closed(self):
        # depth=1 -> 16 slots; 64 probes guarantee two share a nibble.
        tree = VerkleTree(branching=16, depth=1)
        seen = {}
        pair = None
        import hashlib
        for i in range(64):
            key = f"collision-key-{i}".encode()
            nib = hashlib.sha256(b"verkle-tree.v1/key-path\x00" + key
                                 ).hexdigest()[0]
            if nib in seen:
                pair = (seen[nib], key)
                break
            seen[nib] = key
        self.assertIsNotNone(pair)
        k1, k2 = pair
        tree.put(k1, "v1")
        self.assertEqual(tree.get(k1), "v1")
        with self.assertRaises(KeyPathCollisionError):
            tree.put(k2, "v2")
        # the first key is untouched
        self.assertEqual(tree.get(k1), "v1")
        self.assertTrue(issubclass(KeyPathCollisionError, VerkleTreeError))

    def test_deeper_depth_avoids_collision(self):
        tree = VerkleTree(branching=16, depth=64)
        for i in range(50):
            tree.put(f"collision-key-{i}", i)
        for i in range(50):
            self.assertEqual(tree.get(f"collision-key-{i}"), i)


class TestAuditEvents(unittest.TestCase):
    def test_shapes(self):
        e = verkle_audit_event("put", 3, key="alice")
        self.assertEqual(e["schema"], "audit.ndjson/1")
        self.assertEqual(e["module"], SCHEMA_PIN)
        self.assertEqual(e["kind"], "put")
        self.assertEqual(e["audit_seq"], 3)
        self.assertTrue(e["key_pin"].startswith("sha256:"))
        # raw key never appears
        self.assertNotIn("alice", str(e.values()))

        e2 = verkle_audit_event("proof-verified", 0, present=False)
        self.assertFalse(e2["present"])
        e3 = verkle_audit_event("proof-generated", 1)
        self.assertNotIn("key_pin", e3)
        verkle_audit_event("rejected", 2)

    def test_bad_kind_and_seq(self):
        with self.assertRaises(ValueError):
            verkle_audit_event("nope", 0)
        with self.assertRaises(TypeError):
            verkle_audit_event("put", True)
        with self.assertRaises(ValueError):
            verkle_audit_event("put", -1)
        with self.assertRaises(TypeError):
            verkle_audit_event("put", 0, present="yes")


class TestHygiene(unittest.TestCase):
    def test_main_runs(self):
        import verkle_tree
        verkle_tree.main()  # must not raise

    def test_stdlib_only(self):
        path = Path(__file__).resolve().parents[1] / "verkle_tree.py"
        tree = ast.parse(path.read_text())
        allowed = {"__future__", "hashlib", "hmac", "math", "dataclasses",
                   "typing", "json", "canonical_json"}
        imports = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.update(a.name.split(".")[0] for a in node.names)
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    imports.add(node.module.split(".")[0])
        self.assertLessEqual(imports, allowed, f"extra imports: {imports}")


if __name__ == "__main__":
    unittest.main()
