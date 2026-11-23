"""Merkle tree inclusion proofs: tamper-evident anchoring for audit logs.

Builds a binary hash tree over an ordered sequence of leaf digests
(R. C. Merkle, 1988). ``MerkleTree.root()`` pins the whole sequence with
one SHA-256 digest; ``proof(index)`` yields a compact inclusion proof that
``verify`` replays to the root, so a verifier needs only the root — not the
full log — to confirm a leaf was part of the anchored set.

* **Domain separation** — leaves hash with a ``0x00`` prefix, internal
  nodes with ``0x01``. A leaf digest can never be confused with an
  internal node hash, closing the classic leaf/internal second-preimage
  confusion.
* **Odd level** — the last node is duplicated when a level has an odd
  count (the Bitcoin construction). Deterministic and documented; an
  odd tree is not an error.
* **Fail-closed** — empty leaf list rejected at construction (there is no
  honest root for nothing); leaves must be bytes (never silently
  coerced); ``proof`` rejects out-of-range indexes; ``verify`` returns
  ``False`` on any mismatch rather than raising.
* **Audit fit** — ``merkle_tree_audit_event`` shapes the anchored root
  as an ``audit.ndjson/1`` record, so the root can ride the existing
  durable-audit path as a checkpoint.

House style: frozen records, no wall-clock, stdlib-only, deterministic,
version/schema pins, ``main()`` self-check.

Honest scope: an inclusion proof binds *membership*, not veracity — a
proof says "this leaf was in the anchored set", never "this leaf is
true". The tree is a static snapshot: appending means rebuilding (or the
host keeps an append-only discipline on top). Security rests on SHA-256
collision resistance; a second-preimage attack on SHA-256 breaks the
tree, as it breaks every other digest pin in this runtime.

Version pin: merkle-tree.v1
Schema pin: northstar.merkle-tree.v1
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass

MERKLETREE_VERSION = "merkle-tree.v1"
SCHEMA_PIN = "northstar.merkle-tree.v1"

_LEAF_PREFIX = b"\x00"
_NODE_PREFIX = b"\x01"


def _leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(_LEAF_PREFIX + data).digest()


def _node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(_NODE_PREFIX + left + right).digest()


def _require_leaves(leaves) -> tuple:
    if not isinstance(leaves, (list, tuple)):
        raise TypeError(
            f"leaves must be a list or tuple, got {type(leaves).__name__}"
        )
    if len(leaves) == 0:
        raise ValueError("leaves must not be empty: no honest root for nothing")
    frozen = tuple(leaves)
    for i, leaf in enumerate(frozen):
        if not isinstance(leaf, bytes):
            raise TypeError(
                f"leaf {i} must be bytes, got {type(leaf).__name__}"
            )
    return frozen


def _build_levels(leaf_digests: list) -> list:
    """Return the level list; levels[0] is the leaf-digest level."""
    levels = [list(leaf_digests)]
    current = leaf_digests
    while len(current) > 1:
        nxt = []
        for i in range(0, len(current), 2):
            left = current[i]
            right = current[i + 1] if i + 1 < len(current) else left
            nxt.append(_node_hash(left, right))
        levels.append(nxt)
        current = nxt
    return levels


@dataclass(frozen=True)
class MerkleProof:
    """Inclusion proof for one leaf (frozen record).

    ``siblings`` holds the sibling digest at each level, from the leaf
    level upward; ``index`` is the leaf's position in the original order.
    """

    index: int
    leaf_count: int
    leaf_digest: str
    siblings: tuple
    root: str
    schema: str = SCHEMA_PIN

    def __post_init__(self) -> None:
        if isinstance(self.index, bool) or not isinstance(self.index, int):
            raise TypeError("index must be an int")
        if isinstance(self.leaf_count, bool) or not isinstance(self.leaf_count, int):
            raise TypeError("leaf_count must be an int")
        if self.leaf_count < 1:
            raise ValueError("leaf_count must be >= 1")
        if not (0 <= self.index < self.leaf_count):
            raise ValueError("index must be in [0, leaf_count)")
        if not (isinstance(self.leaf_digest, str) and self.leaf_digest.startswith("sha256:")):
            raise ValueError("leaf_digest must be a sha256: pin")
        if not isinstance(self.siblings, tuple):
            raise TypeError("siblings must be a tuple")
        for s in self.siblings:
            if not (isinstance(s, str) and s.startswith("sha256:")):
                raise ValueError("each sibling must be a sha256: pin")
        if not (isinstance(self.root, str) and self.root.startswith("sha256:")):
            raise ValueError("root must be a sha256: pin")

    def as_dict(self) -> dict:
        return {
            "index": self.index,
            "leaf_count": self.leaf_count,
            "leaf_digest": self.leaf_digest,
            "siblings": list(self.siblings),
            "root": self.root,
            "schema": self.schema,
        }


class MerkleTree:
    """Static Merkle tree over an ordered leaf sequence.

    The tree is built once; ``root()`` pins it, ``proof(i)`` extracts an
    inclusion proof for leaf ``i``. Rebuilding on append is the host's
    job — this class never mutates after construction.

    ``build(leaves)`` is the spec entry point (classmethod alias for the
    constructor); ``verify(index, leaf, proof=None)`` replays an
    inclusion proof against this tree's root and returns a bool.
    """

    def __init__(self, leaves) -> None:
        self._leaves = _require_leaves(leaves)
        leaf_digests = [_leaf_hash(leaf) for leaf in self._leaves]
        self._levels = _build_levels(leaf_digests)

    @classmethod
    def build(cls, leaves) -> "MerkleTree":
        """Build (pin) a Merkle tree over an ordered leaf sequence."""
        return cls(leaves)

    @property
    def leaf_count(self) -> int:
        return len(self._leaves)

    @staticmethod
    def _pin(digest: bytes) -> str:
        return "sha256:" + digest.hex()

    def root(self) -> str:
        """The pinned root digest of the whole leaf sequence."""
        return self._pin(self._levels[-1][0])

    def leaf_digest(self, index: int) -> str:
        """Pinned digest of one leaf (the 0x00-prefixed hash)."""
        if isinstance(index, bool) or not isinstance(index, int):
            raise TypeError("index must be an int")
        if not (0 <= index < len(self._leaves)):
            raise ValueError("index out of range")
        return self._pin(self._levels[0][index])

    def proof(self, index: int) -> MerkleProof:
        """Inclusion proof for the leaf at ``index``."""
        if isinstance(index, bool) or not isinstance(index, int):
            raise TypeError("index must be an int")
        if not (0 <= index < len(self._leaves)):
            raise ValueError("index out of range")
        siblings = []
        pos = index
        for level in self._levels[:-1]:
            if pos % 2 == 0:
                sib = level[pos + 1] if pos + 1 < len(level) else level[pos]
            else:
                sib = level[pos - 1]
            siblings.append(self._pin(sib))
            pos //= 2
        return MerkleProof(
            index=index,
            leaf_count=len(self._leaves),
            leaf_digest=self.leaf_digest(index),
            siblings=tuple(siblings),
            root=self.root(),
        )

    def verify(self, index: int, leaf: bytes, proof=None) -> bool:
        """Replay an inclusion proof against this tree's root.

        ``proof`` defaults to ``self.proof(index)``; a caller-supplied
        :class:`MerkleProof` is replayed instead. Returns ``True`` iff the
        leaf is anchored by this tree's root — a mismatch is ``False``,
        never raised (verify-fail is data).
        """
        if isinstance(index, bool) or not isinstance(index, int):
            raise TypeError("index must be an int")
        if not (0 <= index < len(self._leaves)):
            raise ValueError("index out of range")
        pr = self.proof(index) if proof is None else proof
        return verify(pr, leaf, self.root())


def verify(proof: MerkleProof, leaf: bytes, root: str) -> bool:
    """Replay an inclusion proof; True iff ``leaf`` is anchored by ``root``.

    Fail-open is never an option here: any type mismatch, digest
    mismatch, or structural inconsistency returns False, never raises.
    """
    if not isinstance(proof, MerkleProof):
        return False
    if not isinstance(leaf, bytes):
        return False
    if not (isinstance(root, str) and root.startswith("sha256:")):
        return False
    if proof.root != root:
        return False
    try:
        current = _leaf_hash(leaf)
    except Exception:
        return False
    if "sha256:" + current.hex() != proof.leaf_digest:
        return False
    pos = proof.index
    try:
        for sib_pin in proof.siblings:
            sib = bytes.fromhex(sib_pin[len("sha256:"):])
            if pos % 2 == 0:
                current = _node_hash(current, sib)
            else:
                current = _node_hash(sib, current)
            pos //= 2
    except Exception:
        return False
    return hmac.compare_digest("sha256:" + current.hex(), root)


def merkle_tree_audit_event(root: str, leaf_count: int, *, audit_seq: int) -> dict:
    """Shape an anchored root as an ``audit.ndjson/1`` record."""
    if not (isinstance(root, str) and root.startswith("sha256:")):
        raise TypeError("root must be a sha256: pin")
    if isinstance(leaf_count, bool) or not isinstance(leaf_count, int):
        raise TypeError("leaf_count must be an int")
    if leaf_count < 1:
        raise ValueError("leaf_count must be >= 1")
    if isinstance(audit_seq, bool) or not isinstance(audit_seq, int):
        raise TypeError("audit_seq must be an int")
    if audit_seq < 0:
        raise ValueError("audit_seq must be >= 0")
    return {
        "event": "merkle-root-anchored",
        "root": root,
        "leaf_count": leaf_count,
        "audit_seq": audit_seq,
        "schema": SCHEMA_PIN,
    }


def main() -> None:
    leaves = [f"audit-record-{i}".encode() for i in range(7)]  # odd count
    tree = MerkleTree(leaves)
    root = tree.root()
    assert root.startswith("sha256:")
    # Every leaf proves against the same root.
    for i in range(7):
        p = tree.proof(i)
        assert p.root == root
        assert verify(p, leaves[i], root) is True
    # Order matters: shuffled leaves give a different root.
    shuffled = MerkleTree(list(reversed(leaves)))
    assert shuffled.root() != root
    # Tampering is caught.
    p0 = tree.proof(0)
    assert verify(p0, b"tampered", root) is False
    assert verify(p0, leaves[0], "sha256:" + "00" * 32) is False
    # Single-leaf tree: root is the leaf hash, empty proof path.
    single = MerkleTree([b"only"])
    assert len(single.proof(0).siblings) == 0
    assert verify(single.proof(0), b"only", single.root()) is True
    # Spec entry points: build() classmethod and verify() method.
    via_build = MerkleTree.build(leaves)
    assert via_build.root() == root
    for i in range(7):
        assert via_build.verify(i, leaves[i]) is True
    assert via_build.verify(0, b"tampered") is False
    assert via_build.verify(0, leaves[0], proof=via_build.proof(0)) is True
    evt = merkle_tree_audit_event(root, 7, audit_seq=0)
    assert evt["audit_seq"] == 0 and evt["leaf_count"] == 7
    print("merkle-tree OK: root, proofs, verify, tamper-evident, audit")
    return None


if __name__ == "__main__":
    main()
