"""RFC 9162 Merkle proofs over the audit chain: tree, proofs, STH, CLI feed glue.

The structural tests reproduce RFC 9162 §2.1.2's worked 7-leaf example
and §2.1.4.1's consistency examples with independently hand-computed
hashes (plain ``hashlib`` here, not the module under test): if the tree
construction, split rule, or domain separation drifted from the RFC,
these fail.
"""
from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from audit_chain import chain_records, generate_keypair, verify_lines
from audit_merkle import (
    CONSISTENCY_PROOF_VERSION,
    INCLUSION_PROOF_VERSION,
    ConsistencyProof,
    InclusionProof,
    MerkleTree,
    TreeHead,
    consistency_proof_for,
    inclusion_proof_for,
    leaves_from_chain_hashes,
    read_chain_hashes,
    tree_head_for_feed,
    verify_consistency,
    verify_inclusion,
)


def _lh(data: bytes) -> bytes:
    """Independent leaf hash: SHA-256(0x00 || data)."""
    return hashlib.sha256(b"\x00" + data).digest()


def _nd(left: bytes, right: bytes) -> bytes:
    """Independent node hash: SHA-256(0x01 || left || right)."""
    return hashlib.sha256(b"\x01" + left + right).digest()


def _seven_leaves() -> list[bytes]:
    """Seven synthetic 32-byte leaves (stand-ins for chain_hash bytes)."""
    return [hashlib.sha256(f"leaf-{i}".encode()).digest() for i in range(7)]


def _rfc_tree(leaves: list[bytes]) -> dict[str, bytes]:
    """Hand-rolled RFC 9162 §2.1.2 tree for the 7-leaf worked example."""
    a, b, c, d, e, f = (_lh(leaves[i]) for i in range(6))
    g, h, i = _nd(a, b), _nd(c, d), _nd(e, f)
    j = _lh(leaves[6])  # degenerate single-leaf subtree
    k, l = _nd(g, h), _nd(i, j)
    root = _nd(k, l)
    return {"a": a, "b": b, "c": c, "d": d, "e": e, "f": f, "g": g,
            "h": h, "i": i, "j": j, "k": k, "l": l, "root": root}


def _write_feed(directory: str, n: int = 8):
    records = [
        {"schema_version": "audit.ndjson/1", "ts": f"2026-10-03T21:00:{i:02d}Z",
         "component": "test", "event": "probe", "payload": {"i": i}}
        for i in range(n)
    ]
    chained = chain_records(records, component="test")
    feed = Path(directory) / "audit.ndjson"
    feed.write_text("\n".join(json.dumps(r) for r in chained) + "\n", encoding="utf-8")
    return feed, chained


class Rfc9162VectorsTest(unittest.TestCase):
    def test_tree_root_matches_worked_example(self):
        leaves = _seven_leaves()
        nodes = _rfc_tree(leaves)
        self.assertEqual(MerkleTree(leaves).root, nodes["root"])

    def test_inclusion_proofs_match_published_examples(self):
        # RFC 9162 §2.1.2: "The inclusion proof for d0 is [b, h, l]."
        # "for d3 is [c, g, l]", "for d4 is [f, j, k]", "for d6 is [i, k]".
        leaves = _seven_leaves()
        nodes = _rfc_tree(leaves)
        cases = {0: ["b", "h", "l"], 3: ["c", "g", "l"], 4: ["f", "j", "k"], 6: ["i", "k"]}
        for index, names in cases.items():
            proof = inclusion_proof_for(leaves, index)
            self.assertEqual(
                [s.hex() for s in proof.path],
                [nodes[name].hex() for name in names],
                f"index {index}",
            )
            self.assertEqual(proof.root, nodes["root"])
            ok, reason = proof.verify()
            self.assertTrue(ok, reason)

    def test_consistency_examples_verify(self):
        leaves = _seven_leaves()
        full_root = MerkleTree(leaves).root
        # RFC 9162 §2.1.4.1: PROOF(3, D[7]) = [c, d, g, l] (4 nodes),
        # PROOF(4, D[7]) = [l] (1 node), PROOF(6, D[7]) = [i, j, k] (3 nodes).
        for old_size, expected_len in ((3, 4), (4, 1), (6, 3)):
            proof = consistency_proof_for(leaves, old_size)
            self.assertEqual(len(proof.path), expected_len, f"old_size={old_size}")
            self.assertEqual(proof.old_root, MerkleTree(leaves[:old_size]).root)
            self.assertEqual(proof.new_root, full_root)
            ok, reason = proof.verify()
            self.assertTrue(ok, reason)


class InclusionProofTest(unittest.TestCase):
    def test_all_indices_many_sizes(self):
        for size in (1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 31, 32):
            leaves = [hashlib.sha256(f"s{size}-{i}".encode()).digest() for i in range(size)]
            tree = MerkleTree(leaves)
            for index in range(size):
                proof = inclusion_proof_for(leaves, index)
                self.assertEqual(proof.root, tree.root)
                # Audit-path depth is O(log n), never longer than bit_length.
                self.assertLessEqual(len(proof.path), size.bit_length())
                ok, reason = proof.verify()
                self.assertTrue(ok, f"size={size} index={index}: {reason}")
                ok, _ = verify_inclusion(proof.leaf, index, size, proof.path, tree.root)
                self.assertTrue(ok)

    def test_tamper_is_caught(self):
        leaves = _seven_leaves()
        tree = MerkleTree(leaves)
        proof = inclusion_proof_for(leaves, 3)
        good_path = list(proof.path)

        tampered_path = list(good_path)
        tampered_path[0] = bytes([tampered_path[0][0] ^ 0x01]) + tampered_path[0][1:]
        ok, reason = verify_inclusion(proof.leaf, 3, 7, tampered_path, tree.root)
        self.assertFalse(ok)
        self.assertIn("recompute", reason)

        ok, _ = verify_inclusion(proof.leaf, 3, 7, good_path, _lh(b"something-else"))
        self.assertFalse(ok)  # wrong root

        ok, _ = verify_inclusion(proof.leaf, 4, 7, good_path, tree.root)
        self.assertFalse(ok)  # right path, wrong index

        ok, reason = verify_inclusion(proof.leaf, 3, 7, good_path[:-1], tree.root)
        self.assertFalse(ok)  # truncated path
        self.assertIn("needs", reason)

        ok, _ = verify_inclusion(_lh(b"forged-leaf"), 3, 7, good_path, tree.root)
        self.assertFalse(ok)  # forged leaf data

        ok, reason = verify_inclusion(proof.leaf, 9, 7, good_path, tree.root)
        self.assertFalse(ok)
        self.assertIn("out of range", reason)

    def test_single_leaf_tree(self):
        leaves = [hashlib.sha256(b"only").digest()]
        proof = inclusion_proof_for(leaves, 0)
        self.assertEqual(proof.path, [])
        self.assertEqual(proof.root, _lh(leaves[0]))
        self.assertTrue(proof.verify()[0])


class ConsistencyProofTest(unittest.TestCase):
    def test_all_size_pairs(self):
        for new_size in range(2, 25):
            leaves = [hashlib.sha256(f"c{new_size}-{i}".encode()).digest()
                        for i in range(new_size)]
            tree = MerkleTree(leaves)
            for old_size in range(1, new_size):
                proof = consistency_proof_for(leaves, old_size)
                ok, reason = proof.verify()
                self.assertTrue(ok, f"{old_size}->{new_size}: {reason}")
                self.assertEqual(proof.old_root, MerkleTree(leaves[:old_size]).root)
                self.assertEqual(proof.new_root, tree.root)

    def test_tamper_is_caught(self):
        leaves = _seven_leaves()
        tree = MerkleTree(leaves)
        old_root = MerkleTree(leaves[:3]).root
        proof = consistency_proof_for(leaves, 3)

        ok, reason = verify_consistency(_lh(b"rewritten"), 3, tree.root, 7, proof.path)
        self.assertFalse(ok)
        self.assertIn("old tree head", reason)

        ok, reason = verify_consistency(old_root, 3, _lh(b"forged"), 7, proof.path)
        self.assertFalse(ok)
        self.assertIn("new tree head", reason)

        ok, _ = verify_consistency(old_root, 3, tree.root, 7, proof.path[:-1])
        self.assertFalse(ok)  # truncated proof cannot recompute both roots

        # Same size, different roots: a forked history, not a consistent extension.
        ok, reason = verify_consistency(old_root, 7, tree.root, 7, [])
        self.assertFalse(ok)
        self.assertIn("forked", reason)

        ok, _ = verify_consistency(tree.root, 7, tree.root, 7, [])
        self.assertTrue(ok)

        ok, _ = verify_consistency(tree.root, 8, tree.root, 7, [])
        self.assertFalse(ok)  # old_size > new_size is not an extension

    def test_bad_sizes_rejected(self):
        leaves = _seven_leaves()
        with self.assertRaises(ValueError):
            consistency_proof_for(leaves, 0)
        with self.assertRaises(ValueError):
            consistency_proof_for(leaves, 7)
        with self.assertRaises(ValueError):
            consistency_proof_for(leaves, 9)


class ProofSerializationTest(unittest.TestCase):
    def test_json_roundtrip(self):
        leaves = _seven_leaves()
        inclusion = inclusion_proof_for(leaves, 2)
        doc = inclusion.to_dict()
        self.assertEqual(doc["proof"], INCLUSION_PROOF_VERSION)
        back = InclusionProof.from_dict(json.loads(json.dumps(doc)))
        self.assertEqual(back.to_dict(), doc)
        self.assertTrue(back.verify()[0])

        consistency = consistency_proof_for(leaves, 5)
        doc = consistency.to_dict()
        self.assertEqual(doc["proof"], CONSISTENCY_PROOF_VERSION)
        back = ConsistencyProof.from_dict(json.loads(json.dumps(doc)))
        self.assertEqual(back.to_dict(), doc)
        self.assertTrue(back.verify()[0])

    def test_rejects_garbage(self):
        for bad in ({}, {"proof": "nope"}, {"proof": INCLUSION_PROOF_VERSION},
                    {"proof": CONSISTENCY_PROOF_VERSION}):
            with self.assertRaises(ValueError):
                InclusionProof.from_dict(bad)
            with self.assertRaises(ValueError):
                ConsistencyProof.from_dict(bad)


class SignedTreeHeadTest(unittest.TestCase):
    def test_sign_and_verify(self):
        leaves = _seven_leaves()
        tree = MerkleTree(leaves)
        head = TreeHead(tree_size=7, root=tree.root)
        seed, pubkey = generate_keypair()
        signed = head.sign(seed)
        self.assertTrue(signed.verify_signature(pubkey))
        self.assertFalse(head.verify_signature(pubkey))  # unsigned: nothing to check
        # A transplanted root invalidates the signature.
        forged = TreeHead(tree_size=7, root=_lh(b"other"), signature=signed.signature)
        self.assertFalse(forged.verify_signature(pubkey))
        # Wrong key fails.
        _, other_pub = generate_keypair()
        self.assertFalse(signed.verify_signature(other_pub))
        # JSON roundtrip preserves the signature.
        restored = TreeHead.from_dict(json.loads(json.dumps(signed.to_dict())))
        self.assertTrue(restored.verify_signature(pubkey))


class FeedIntegrationTest(unittest.TestCase):
    def test_prove_and_verify_over_feed(self):
        with tempfile.TemporaryDirectory() as directory:
            feed, chained = _write_feed(directory)
            self.assertTrue(verify_lines(feed.read_text(encoding="utf-8").splitlines()).ok)

            head = tree_head_for_feed(feed)
            self.assertEqual(head.tree_size, 8)
            leaves = leaves_from_chain_hashes(read_chain_hashes(feed))
            self.assertEqual(len(leaves), 8)

            for index in range(8):
                proof = inclusion_proof_for(leaves, index)
                self.assertEqual(proof.leaf.hex(), chained[index]["chain_hash"])
                ok, reason = proof.verify()
                self.assertTrue(ok, reason)

            proof = consistency_proof_for(leaves, 5)
            ok, reason = proof.verify()
            self.assertTrue(ok, reason)

    def test_tamper_breaks_chain_and_inclusion(self):
        from audit_chain import chain_record

        with tempfile.TemporaryDirectory() as directory:
            feed, chained = _write_feed(directory)
            leaves = leaves_from_chain_hashes(read_chain_hashes(feed))
            old_root = MerkleTree(leaves).root
            proof = inclusion_proof_for(leaves, 3)

            # Naive edit without re-sealing: the chain catches it.
            tampered = dict(chained[3])
            tampered["payload"] = {"i": 999}
            lines = [json.dumps(r) for r in chained]
            lines[3] = json.dumps(tampered)
            self.assertFalse(verify_lines(lines).ok)

            # Stronger attacker: rewrites record 3 and re-seals the chain
            # from there — a "fresh chain" the bare chain cannot see without
            # an anchor. The new chain verifies on its own...
            resealed = list(chained[:3])
            prev = chained[2]["chain_hash"]
            bodies = []
            for record in chained[3:]:
                body = {k: v for k, v in record.items()
                        if k not in ("prev_hash", "chain_hash", "signature")}
                bodies.append(body)
            bodies[0]["payload"] = {"i": 999}
            for body in bodies:
                sealed = chain_record(body, prev)
                resealed.append(sealed)
                prev = sealed["chain_hash"]
            self.assertTrue(
                verify_lines([json.dumps(r) for r in resealed]).ok
            )
            # ...but the rewritten record is NOT in the log the old head
            # commits to: its new leaf fails the old inclusion proof.
            new_leaves = leaves_from_chain_hashes(r["chain_hash"] for r in resealed)
            self.assertNotEqual(new_leaves[3], proof.leaf)
            ok, _ = verify_inclusion(new_leaves[3], 3, 8, proof.path, old_root)
            self.assertFalse(ok)
            # And the old proof's leaf no longer binds to the rewritten record.
            ok, _ = verify_inclusion(proof.leaf, 3, 8, proof.path, old_root)
            self.assertTrue(ok)  # the ORIGINAL record still verifies

    def test_unsealed_feed_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            feed = Path(directory) / "audit.ndjson"
            feed.write_text('{"schema_version": "audit.ndjson/1", "event": "x"}\n',
                            encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "not a sealed log"):
                read_chain_hashes(feed)
            empty = Path(directory) / "empty.ndjson"
            empty.write_text("", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "no records"):
                read_chain_hashes(empty)

    def test_bad_leaves_rejected(self):
        with self.assertRaises(ValueError):
            MerkleTree([b"too short"])
        # RFC 9162: MTH({}) = HASH() — the empty tree has a defined root.
        self.assertEqual(MerkleTree([]).root, hashlib.sha256(b"").digest())


if __name__ == "__main__":
    unittest.main()
