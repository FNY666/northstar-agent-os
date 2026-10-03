"""RFC 9162 Merkle proofs for the ``audit.ndjson/1`` chained feed.

The hash chain (``audit_chain``) makes ``audit verify`` an O(n) full scan:
every link is recomputed from the genesis anchor. That is the right default
for a first verification, but it does not scale to the question verifiers
ask most often — *"is this one record in the log?"* — and it gives a
verifier holding an old tree head no way to move to a new head without
re-scanning.

This module adds the standard transparency-log answer (RFC 9162, which
obsoletes RFC 6962; the tree construction is identical):

* **Merkle inclusion proof** (§2.1.1): O(log n) proof that one leaf is in
  the tree behind a tree head.
* **Consistency proof** (§2.1.4.1): O(log n) proof that a newer tree head
  is a consistent extension of an older one — the old log is a prefix of
  the new log, so history was appended to, not rewritten.

Design decisions, stated plainly:

* **Leaves are the sealed chain hashes.** Leaf ``i`` is the raw 32 bytes
  of record ``i``'s ``chain_hash``. The Merkle tree therefore commits to
  the *sealed chain*, not to raw record bytes: an inclusion proof says
  "the record sealed at chain position ``i`` is in this log", and the
  existing chain machinery (``audit_chain.verify_lines``) says what that
  record contains. This keeps one integrity story instead of two.
* **Exact RFC 9162 §2.1 construction**: ``leaf = SHA-256(0x00 || data)``,
  ``node = SHA-256(0x01 || left || right)``, and for ``n > 1`` leaves the
  split point ``k`` is the largest power of two strictly smaller than
  ``n``. The RFC's worked examples (§2.1.2's 7-leaf tree, §2.1.4.1's
  ``PROOF(3,D[7])`` / ``PROOF(4,D[7])`` / ``PROOF(6,D[7])``) are encoded
  as test vectors in ``tests/test_audit_merkle.py`` and pass.
* This is **not** the draft-sharif-agent-audit-trail §6.4 "odd node
  promoted unchanged" variant — that variant differs from RFC 9162, so a
  verifier implementing the RFC would not reproduce our roots. We follow
  the RFC; the alignment doc records the difference.
* Proofs **complement** the chain and the Rekor external anchor; they do
  not replace them. A proof is only meaningful over an intact chain —
  the CLI refuses to mint proofs for a feed whose chain does not verify.
  A bare tree head, like a bare chain, does not stop wholesale history
  rewrites: heads must be anchored or signed (``TreeHead.sign``) and the
  verifier must compare against a head it already trusts.

Everything here is offline and deterministic. No network, no clock reads.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

#: Version stamp on inclusion-proof JSON documents.
INCLUSION_PROOF_VERSION = "northstar-audit-merkle-proof/1"

#: Version stamp on consistency-proof JSON documents.
CONSISTENCY_PROOF_VERSION = "northstar-audit-merkle-consistency/1"

#: Version stamp on signed tree head (STH) JSON documents.
STH_VERSION = "northstar-audit-sth/1"

_HASH_SIZE = 32
_HEX64_RE = __import__("re").compile(r"^[0-9a-f]{64}$")


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _largest_pow2_lt(n: int) -> int:
    """Largest power of two strictly smaller than ``n`` (``n > 1``).

    RFC 9162 §2.1: "let k be the largest power of two smaller than n
    (i.e., k < n <= 2k)". The tree shape is uniquely determined by n.
    """
    if n <= 1:
        raise ValueError("need n > 1 for a split point")
    return 1 << (n - 1).bit_length() - 1


def _leaf_hash(leaf_data: bytes) -> bytes:
    """RFC 9162 §2.1: ``MTH({d[0]}) = HASH(0x00 || d[0])`` (domain separation)."""
    return _sha256(b"\x00" + leaf_data)


def _node_hash(left: bytes, right: bytes) -> bytes:
    """RFC 9162 §2.1: ``MTH(D_n) = HASH(0x01 || MTH(left) || MTH(right))``."""
    return _sha256(b"\x01" + left + right)


class MerkleTree:
    """A memoized RFC 9162 Merkle tree over an ordered leaf list.

    ``leaves[i]`` is the leaf *data* (here: raw ``chain_hash`` bytes);
    hashing adds the RFC's domain-separation prefixes. Subtree hashes are
    memoized so proof generation over an n-leaf tree costs O(n), not
    O(n log n).
    """

    def __init__(self, leaves: list[bytes]):
        for index, leaf in enumerate(leaves):
            if not isinstance(leaf, bytes) or len(leaf) != _HASH_SIZE:
                raise ValueError(
                    f"leaf {index} must be {_HASH_SIZE} raw bytes, "
                    f"got {type(leaf).__name__} of length {len(leaf) if isinstance(leaf, bytes) else '?'}"
                )
        self.leaves = list(leaves)
        self._cache: dict[tuple[int, int], bytes] = {}

    @property
    def size(self) -> int:
        return len(self.leaves)

    def subtree(self, start: int, size: int) -> bytes:
        """Root hash of leaves ``[start, start+size)`` (RFC 9162 §2.1)."""
        if not (0 <= start < len(self.leaves)) or size < 1 or start + size > len(self.leaves):
            raise ValueError(f"subtree [{start}, {start + size}) out of range for {len(self.leaves)} leaves")
        key = (start, size)
        cached = self._cache.get(key)
        if cached is not None:
            return cached
        if size == 1:
            result = _leaf_hash(self.leaves[start])
        else:
            k = _largest_pow2_lt(size)
            result = _node_hash(self.subtree(start, k), self.subtree(start + k, size - k))
        self._cache[key] = result
        return result

    @property
    def root(self) -> bytes:
        """The tree head hash for all leaves (``MTH({}) = HASH()`` when empty)."""
        if not self.leaves:
            return _sha256(b"")
        return self.subtree(0, len(self.leaves))


@dataclass
class TreeHead:
    """A signed-tree-head-style log head: ``(tree_size, root_hash)``.

    Mirrors CT's STH: the pair a verifier pins and compares. ``sign()``
    binds size and root with Ed25519 so a head can be published; the
    signature is over the canonical JSON of the unsigned head document,
    so third parties reproduce the exact signed bytes.
    """

    tree_size: int
    root: bytes  # 32 raw bytes
    signature: bytes | None = None  # 64 raw bytes when signed

    def __post_init__(self) -> None:
        if self.tree_size < 0:
            raise ValueError("tree_size must be >= 0")
        if len(self.root) != _HASH_SIZE:
            raise ValueError("root must be 32 raw bytes")
        if self.signature is not None and len(self.signature) != 64:
            raise ValueError("signature must be 64 raw bytes")

    def _unsigned_dict(self) -> dict[str, Any]:
        return {"sth": STH_VERSION, "tree_size": self.tree_size, "root": self.root.hex()}

    def to_dict(self) -> dict[str, Any]:
        doc = self._unsigned_dict()
        if self.signature is not None:
            doc["signature"] = self.signature.hex()
        return doc

    @classmethod
    def from_dict(cls, doc: Any) -> "TreeHead":
        if not isinstance(doc, dict) or doc.get("sth") != STH_VERSION:
            raise ValueError("not a northstar signed tree head document")
        tree_size = doc.get("tree_size")
        root = doc.get("root")
        if not isinstance(tree_size, int) or not isinstance(root, str) or not _HEX64_RE.match(root):
            raise ValueError("malformed tree head (tree_size/root)")
        signature = doc.get("signature")
        sig_bytes: bytes | None = None
        if signature is not None:
            if not isinstance(signature, str):
                raise ValueError("malformed tree head signature")
            try:
                sig_bytes = bytes.fromhex(signature)
            except ValueError:
                raise ValueError("malformed tree head signature")
            if len(sig_bytes) != 64:
                raise ValueError("malformed tree head signature")
        return cls(tree_size=tree_size, root=bytes.fromhex(root), signature=sig_bytes)

    def sign(self, seed: bytes) -> "TreeHead":
        """Return a copy with an Ed25519 signature over the unsigned head."""
        from ed25519 import sign

        if len(seed) != 32:
            raise ValueError("seed must be 32 bytes")
        canonical = json.dumps(self._unsigned_dict(), sort_keys=True, separators=(",", ":")).encode("utf-8")
        return TreeHead(tree_size=self.tree_size, root=self.root, signature=sign(seed, canonical))

    def verify_signature(self, public_key: bytes) -> bool:
        """Check the head's Ed25519 signature; False when absent or invalid."""
        from ed25519 import verify

        if self.signature is None or len(public_key) != 32:
            return False
        canonical = json.dumps(self._unsigned_dict(), sort_keys=True, separators=(",", ":")).encode("utf-8")
        return verify(public_key, canonical, self.signature)


@dataclass
class InclusionProof:
    """RFC 9162 §2.1.1 audit path: leaf ``leaf_index`` is in the tree.

    ``path`` is ordered leaf-adjacent first (the RFC's convention: "The
    inclusion proof for d0 is [b, h, l]"), so a verifier folds it
    bottom-up. ``leaf`` is the leaf *data* (raw ``chain_hash`` bytes);
    the verifier recomputes the leaf hash itself, so a proof never asks
    the verifier to trust a pre-hashed leaf.
    """

    tree_size: int
    leaf_index: int
    leaf: bytes  # 32 raw bytes: the record's chain_hash
    root: bytes  # 32 raw bytes: the tree head this proves against
    path: list[bytes] = field(default_factory=list)  # sibling hashes, leaf-first

    def __post_init__(self) -> None:
        if not (0 <= self.leaf_index < self.tree_size):
            raise ValueError("leaf_index out of range for tree_size")
        for name, value in (("leaf", self.leaf), ("root", self.root)):
            if len(value) != _HASH_SIZE:
                raise ValueError(f"{name} must be 32 raw bytes")
        for sibling in self.path:
            if len(sibling) != _HASH_SIZE:
                raise ValueError("every path element must be 32 raw bytes")

    def to_dict(self) -> dict[str, Any]:
        return {
            "proof": INCLUSION_PROOF_VERSION,
            "tree_size": self.tree_size,
            "leaf_index": self.leaf_index,
            "leaf": self.leaf.hex(),
            "root": self.root.hex(),
            "path": [sibling.hex() for sibling in self.path],
        }

    @classmethod
    def from_dict(cls, doc: Any) -> "InclusionProof":
        if not isinstance(doc, dict) or doc.get("proof") != INCLUSION_PROOF_VERSION:
            raise ValueError("not a northstar Merkle inclusion proof document")

        def _hex32(value: Any, name: str) -> bytes:
            if not isinstance(value, str) or not _HEX64_RE.match(value):
                raise ValueError(f"malformed inclusion proof field {name!r}")
            return bytes.fromhex(value)

        tree_size = doc.get("tree_size")
        leaf_index = doc.get("leaf_index")
        path = doc.get("path")
        if not isinstance(tree_size, int) or not isinstance(leaf_index, int) or not isinstance(path, list):
            raise ValueError("malformed inclusion proof (tree_size/leaf_index/path)")
        return cls(
            tree_size=tree_size,
            leaf_index=leaf_index,
            leaf=_hex32(doc.get("leaf"), "leaf"),
            root=_hex32(doc.get("root"), "root"),
            path=[_hex32(item, f"path[{i}]") for i, item in enumerate(path)],
        )

    def verify(self) -> tuple[bool, str]:
        """O(log n) check: fold the audit path and compare with ``root``."""
        return verify_inclusion(self.leaf, self.leaf_index, self.tree_size, self.path, self.root)


@dataclass
class ConsistencyProof:
    """RFC 9162 §2.1.4.1: the ``new_size`` tree extends the ``old_size`` tree.

    ``path`` is in generation order (post-order: each node's children
    precede it within its subtree), which is the order the verifier
    consumes. The proof lets a verifier holding a trusted ``(old_size,
    old_root)`` move to ``(new_size, new_root)`` without re-scanning.
    """

    old_size: int
    new_size: int
    old_root: bytes
    new_root: bytes
    path: list[bytes] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not (0 < self.old_size <= self.new_size):
            raise ValueError("need 0 < old_size <= new_size")
        for name, value in (("old_root", self.old_root), ("new_root", self.new_root)):
            if len(value) != _HASH_SIZE:
                raise ValueError(f"{name} must be 32 raw bytes")
        for node in self.path:
            if len(node) != _HASH_SIZE:
                raise ValueError("every path element must be 32 raw bytes")

    def to_dict(self) -> dict[str, Any]:
        return {
            "proof": CONSISTENCY_PROOF_VERSION,
            "old_size": self.old_size,
            "new_size": self.new_size,
            "old_root": self.old_root.hex(),
            "new_root": self.new_root.hex(),
            "path": [node.hex() for node in self.path],
        }

    @classmethod
    def from_dict(cls, doc: Any) -> "ConsistencyProof":
        if not isinstance(doc, dict) or doc.get("proof") != CONSISTENCY_PROOF_VERSION:
            raise ValueError("not a northstar Merkle consistency proof document")

        def _hex32(value: Any, name: str) -> bytes:
            if not isinstance(value, str) or not _HEX64_RE.match(value):
                raise ValueError(f"malformed consistency proof field {name!r}")
            return bytes.fromhex(value)

        old_size = doc.get("old_size")
        new_size = doc.get("new_size")
        path = doc.get("path")
        if not isinstance(old_size, int) or not isinstance(new_size, int) or not isinstance(path, list):
            raise ValueError("malformed consistency proof (old_size/new_size/path)")
        return cls(
            old_size=old_size,
            new_size=new_size,
            old_root=_hex32(doc.get("old_root"), "old_root"),
            new_root=_hex32(doc.get("new_root"), "new_root"),
            path=[_hex32(item, f"path[{i}]") for i, item in enumerate(path)],
        )

    def verify(self) -> tuple[bool, str]:
        """O(log n) check: recompute both roots from the proof and compare."""
        return verify_consistency(
            self.old_root, self.old_size, self.new_root, self.new_size, self.path
        )


def inclusion_proof_for(leaves: list[bytes], index: int) -> InclusionProof:
    """Build the RFC 9162 §2.1.1 audit path for leaf ``index`` (O(n) build)."""
    tree = MerkleTree(leaves)
    if not (0 <= index < tree.size):
        raise ValueError(f"leaf index {index} out of range for {tree.size} leaves")
    path: list[bytes] = []

    def _collect(start: int, size: int, rel: int) -> None:
        if size == 1:
            return
        k = _largest_pow2_lt(size)
        if rel < k:
            _collect(start, k, rel)
            path.append(tree.subtree(start + k, size - k))  # right sibling
        else:
            _collect(start + k, size - k, rel - k)
            path.append(tree.subtree(start, k))  # left sibling

    _collect(0, tree.size, index)
    return InclusionProof(
        tree_size=tree.size,
        leaf_index=index,
        leaf=tree.leaves[index],
        root=tree.root,
        path=path,
    )


def verify_inclusion(
    leaf: bytes,
    index: int,
    tree_size: int,
    path: list[bytes],
    root: bytes,
) -> tuple[bool, str]:
    """O(log n) inclusion check; ``(ok, reason)`` — never raises on bad input."""
    if len(leaf) != _HASH_SIZE or len(root) != _HASH_SIZE:
        return False, "leaf and root must be 32 bytes"
    if not (0 <= index < tree_size):
        return False, f"leaf index {index} out of range for tree size {tree_size}"
    if any(len(sibling) != _HASH_SIZE for sibling in path):
        return False, "every path element must be 32 bytes"
    # Walk top-down recording left/right decisions, then fold bottom-up:
    # path[0] is the leaf-adjacent sibling (the RFC's ordering).
    decisions: list[bool] = []  # True when the current node is a left child
    cursor, size = index, tree_size
    while size > 1:
        k = _largest_pow2_lt(size)
        if cursor < k:
            decisions.append(True)
            size = k
        else:
            decisions.append(False)
            cursor -= k
            size -= k
    if len(path) != len(decisions):
        return False, (
            f"path has {len(path)} elements but a tree of size {tree_size} "
            f"needs {len(decisions)}"
        )
    current = _leaf_hash(leaf)
    for sibling, is_left in zip(path, reversed(decisions)):
        current = _node_hash(current, sibling) if is_left else _node_hash(sibling, current)
    if current != root:
        return False, "audit path does not recompute to the tree head (record not in this log)"
    return True, f"leaf {index} is in the tree of size {tree_size}"


def consistency_proof_for(leaves: list[bytes], old_size: int) -> ConsistencyProof:
    """Build the RFC 9162 §2.1.4.1 proof that the tree extends ``old_size``."""
    tree = MerkleTree(leaves)
    new_size = tree.size
    if not (0 < old_size < new_size):
        raise ValueError(f"need 0 < old_size < new_size, got {old_size} < {new_size}")
    path: list[bytes] = []

    def _collect(start: int, old: int, new: int) -> None:
        # Prove [start, start+new) extends [start, start+old).
        if old == new:
            if not (start == 0 and old == old_size):
                # A subtree of the old tree the verifier cannot recompute
                # from its trusted old root alone: hand it over explicitly.
                # (When start == 0 and old == old_size this subtree IS the
                # whole old tree, whose root the verifier already holds —
                # cf. RFC 9162's PROOF(4, D[7]) = [l].)
                path.append(tree.subtree(start, old))
            return
        k = _largest_pow2_lt(new)
        if old <= k:
            _collect(start, old, k)
            path.append(tree.subtree(start + k, new - k))
        else:
            _collect(start + k, old - k, new - k)
            path.append(tree.subtree(start, k))

    _collect(0, old_size, new_size)
    return ConsistencyProof(
        old_size=old_size,
        new_size=new_size,
        old_root=tree.subtree(0, old_size),
        new_root=tree.root,
        path=path,
    )


def verify_consistency(
    old_root: bytes,
    old_size: int,
    new_root: bytes,
    new_size: int,
    path: list[bytes],
) -> tuple[bool, str]:
    """O(log n) consistency check; ``(ok, reason)`` — never raises on bad input."""
    if len(old_root) != _HASH_SIZE or len(new_root) != _HASH_SIZE:
        return False, "old_root and new_root must be 32 bytes"
    if not (0 < old_size <= new_size):
        return False, f"need 0 < old_size <= new_size, got {old_size} <= {new_size}"
    if any(len(node) != _HASH_SIZE for node in path):
        return False, "every path element must be 32 bytes"
    if old_size == new_size:
        if path:
            return False, "identical tree sizes need an empty proof"
        if old_root != new_root:
            return False, "same tree size but different roots (forked history)"
        return True, "identical tree heads"
    # Mirror _collect: consume the proof in generation order, recomputing
    # both the old subtree root and the new subtree root at each level.
    nodes = list(path)

    def _fold(start: int, old: int, new: int) -> tuple[bytes, bytes] | None:
        # Returns (old_subtree_root, new_subtree_root), or None on exhaustion.
        if old == new:
            if start == 0 and old == old_size:
                return old_root, old_root
            if not nodes:
                return None
            claimed = nodes.pop(0)
            return claimed, claimed
        k = _largest_pow2_lt(new)
        if old <= k:
            sub = _fold(start, old, k)
            if sub is None or not nodes:
                return None
            old_sub, left = sub
            right = nodes.pop(0)
            return old_sub, _node_hash(left, right)
        sub = _fold(start + k, old - k, new - k)
        if sub is None or not nodes:
            return None
        old_right, new_right = sub
        left = nodes.pop(0)
        return _node_hash(left, old_right), _node_hash(left, new_right)

    result = _fold(0, old_size, new_size)
    if result is None:
        return False, "proof exhausted before both roots were recomputed"
    if nodes:
        return False, f"proof has {len(nodes)} unconsumed node(s)"
    recomputed_old, recomputed_new = result
    if recomputed_old != old_root:
        return False, "proof does not recompute the old tree head (history rewritten)"
    if recomputed_new != new_root:
        return False, "proof does not recompute the new tree head"
    return True, f"tree of size {new_size} consistently extends size {old_size}"


def read_chain_hashes(feed: str | Path) -> list[str]:
    """Raw ``chain_hash`` hexes of every record in a feed, in order.

    Every record must carry a well-formed ``chain_hash``; a feed with a
    hole is not a log and this raises ``ValueError`` naming the line.
    (Proving inclusion in a broken chain is meaningless — the CLI checks
    chain integrity before minting proofs.)
    """
    hashes: list[str] = []
    with open(feed, "r", encoding="utf-8") as handle:
        for number, raw in enumerate(handle, start=1):
            line = raw.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as error:
                raise ValueError(f"line {number} is not valid JSON: {error}") from error
            chain_hash = record.get("chain_hash") if isinstance(record, dict) else None
            if not isinstance(chain_hash, str) or not _HEX64_RE.match(chain_hash):
                raise ValueError(f"line {number}: missing or malformed chain_hash (not a sealed log)")
            hashes.append(chain_hash)
    if not hashes:
        raise ValueError("feed has no records")
    return hashes


def leaves_from_chain_hashes(chain_hashes: Iterable[str]) -> list[bytes]:
    """Leaf data for the tree: raw 32 bytes of each ``chain_hash`` hex."""
    leaves: list[bytes] = []
    for index, hexed in enumerate(chain_hashes):
        if not isinstance(hexed, str) or not _HEX64_RE.match(hexed):
            raise ValueError(f"chain_hash {index} is not 64 lowercase hex characters")
        leaves.append(bytes.fromhex(hexed))
    if not leaves:
        raise ValueError("need at least one leaf")
    return leaves


def tree_head_for_feed(feed: str | Path) -> TreeHead:
    """The ``(tree_size, root)`` head of a feed's Merkle tree."""
    leaves = leaves_from_chain_hashes(read_chain_hashes(feed))
    tree = MerkleTree(leaves)
    return TreeHead(tree_size=tree.size, root=tree.root)
