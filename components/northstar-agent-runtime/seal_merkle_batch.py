"""Merkle batch checkpoints for sealed ledgers, Simulated.

P1 absorption from the exhaustive method search: Crosby-Wallach /
MMR-style batched Merkle checkpoints.  A forward-seal ledger seals
records one by one (P0); this module batches a contiguous run of
sealed records into one Merkle tree so a verifier holding only the
batch root can confirm any single record's membership in O(log n)
hashes -- without holding the full log.

Design (stdlib-only, no sibling imports -- the Merkle construction is
reimplemented here with domain separation rather than importing
``merkle_tree.py``, so this module stays self-contained):

* Leaves: ``SHA256(0x00 || record_hash_bytes)`` where record_hash is
  the ``sha256:`` hex pin of a forward-seal record.
* Internal nodes: ``SHA256(0x01 || left || right)``.
* Odd level: last node duplicated (Bitcoin construction).
* The batch root is pinned as ``sha256:`` hex and can be sealed into
  a forward-seal checkpoint (or published / timestamped externally --
  the OpenTimestamps P1 anchoring is the host's job).

API::

    batch = seal_batch(record_hashes)   # -> MerkleBatch (frozen)
    proof = batch.proof(index)          # -> MerkleProof (frozen)
    ok = verify_proof(record_hash, proof, batch.root)

Fail-closed: empty batch rejected; non-``sha256:`` leaves rejected;
out-of-range proof index rejected; ``verify_proof`` returns False on
any mismatch (never raises on bad proof data, raises only on bad
*arguments* like wrong types).

Honest scope: an inclusion proof binds *membership* ("this record was
in the anchored batch"), never veracity ("this record is true") and
never completeness ("no records were omitted").  A batch is a static
snapshot; appending means sealing a new batch.  Security rests on
SHA-256 collision resistance.

House style: frozen dataclasses, no wall-clock, RLock not needed
(pure functions on immutable inputs), stdlib-only, ``sha256:`` pins,
version/schema pins, ``stdlib_only()`` + ``main()`` self-check.
"""

from __future__ import annotations

import ast
import hashlib
from dataclasses import dataclass
from typing import List, Sequence, Tuple

#: Module version pin.
SEAL_MERKLE_BATCH_VERSION = "seal-merkle-batch.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.seal-merkle-batch.v1"

_LEAF_PREFIX = b"\x00"
_NODE_PREFIX = b"\x01"


def _leaf_hash(record_hash_hex: str) -> bytes:
    raw = bytes.fromhex(record_hash_hex[7:])  # strip "sha256:" prefix
    return hashlib.sha256(_LEAF_PREFIX + raw).digest()


def _node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(_NODE_PREFIX + left + right).digest()


def _require_pin(value: str) -> None:
    if not isinstance(value, str):
        raise MerkleBatchError("record hash must be str")
    if not value.startswith("sha256:") or len(value) != 71:
        raise MerkleBatchError("record hash must be a sha256: pin")
    try:
        bytes.fromhex(value[7:])
    except ValueError:
        raise MerkleBatchError("record hash hex is malformed")


class MerkleBatchError(Exception):
    """Fail-closed: bad batch arguments raise, never produce bad roots."""


@dataclass(frozen=True)
class MerkleProof:
    """O(log n) inclusion proof for one leaf (immutable)."""

    leaf_index: int
    leaf_hash: str  # sha256: pin of the leaf's record hash
    siblings: Tuple[str, ...]  # hex digests bottom-up
    # For each sibling, True if the sibling is on the LEFT of the
    # current node (i.e. node = H(sibling || current)), False if RIGHT.
    sibling_is_left: Tuple[bool, ...]
    root: str  # sha256: pin this proof claims


@dataclass(frozen=True)
class MerkleBatch:
    """A sealed batch: Merkle tree over a contiguous record run."""

    first_seq: int  # 1-based seq of the first record in the batch
    record_hashes: Tuple[str, ...]  # sha256: pins, in seq order
    root: str  # sha256: pin of the Merkle root
    depth: int  # tree depth (0 for a single leaf)

    def proof(self, index: int) -> MerkleProof:
        """Return the inclusion proof for the 0-based ``index``."""
        if isinstance(index, bool) or not isinstance(index, int):
            raise MerkleBatchError("index must be int")
        n = len(self.record_hashes)
        if index < 0 or index >= n:
            raise MerkleBatchError("index out of range")
        # Rebuild the tree level by level, tracking the proof path.
        level: List[bytes] = [_leaf_hash(h) for h in self.record_hashes]
        pos = index
        siblings: List[str] = []
        is_left: List[bool] = []
        while len(level) > 1:
            if len(level) % 2 == 1:
                level = level + [level[-1]]
            sibling_pos = pos ^ 1
            siblings.append(level[sibling_pos].hex())
            # Sibling is left when our position is odd (we are right).
            is_left.append(pos % 2 == 1)
            nxt: List[bytes] = []
            for i in range(0, len(level), 2):
                nxt.append(_node_hash(level[i], level[i + 1]))
            level = nxt
            pos //= 2
        return MerkleProof(
            leaf_index=index,
            leaf_hash=self.record_hashes[index],
            siblings=tuple(siblings),
            sibling_is_left=tuple(is_left),
            root=self.root,
        )


def seal_batch(record_hashes: Sequence[str], first_seq: int = 1) -> MerkleBatch:
    """Seal a contiguous run of record hashes into a Merkle batch.

    ``record_hashes`` must be non-empty ``sha256:`` pins in seq order;
    ``first_seq`` is the 1-based seq of the first record (for audit
    bookkeeping; it does not affect the root).
    """
    if isinstance(first_seq, bool) or not isinstance(first_seq, int):
        raise MerkleBatchError("first_seq must be int")
    if first_seq < 1:
        raise MerkleBatchError("first_seq must be >= 1")
    hashes = tuple(record_hashes)
    if not hashes:
        raise MerkleBatchError("cannot seal an empty batch")
    for h in hashes:
        _require_pin(h)

    level: List[bytes] = [_leaf_hash(h) for h in hashes]
    depth = 0
    while len(level) > 1:
        if len(level) % 2 == 1:
            level = level + [level[-1]]
        nxt: List[bytes] = []
        for i in range(0, len(level), 2):
            nxt.append(_node_hash(level[i], level[i + 1]))
        level = nxt
        depth += 1
    root = "sha256:" + level[0].hex()
    return MerkleBatch(
        first_seq=first_seq,
        record_hashes=hashes,
        root=root,
        depth=depth,
    )


def verify_proof(record_hash: str, proof: MerkleProof, root: str) -> bool:
    """Verify an inclusion proof against ``root`` (pure function).

    Returns True iff ``record_hash`` is the leaf at ``proof.leaf_index``
    and the sibling hashes replay to ``root``.  Returns False on any
    mismatch; raises MerkleBatchError only on malformed arguments.
    """
    _require_pin(record_hash)
    if not isinstance(proof, MerkleProof):
        raise MerkleBatchError("proof must be MerkleProof")
    _require_pin(root)
    if len(proof.siblings) != len(proof.sibling_is_left):
        return False
    if proof.leaf_hash != record_hash:
        return False
    try:
        current = _leaf_hash(record_hash)
    except Exception:
        return False
    for sib_hex, left in zip(proof.siblings, proof.sibling_is_left):
        try:
            sib = bytes.fromhex(sib_hex)
        except ValueError:
            return False
        if len(sib) != 32:
            return False
        current = _node_hash(sib, current) if left else _node_hash(current, sib)
    computed_root = "sha256:" + current.hex()
    return computed_root == root == proof.root


def stdlib_only() -> bool:
    """AST check: this module imports stdlib modules only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {
        "__future__",
        "ast",
        "dataclasses",
        "hashlib",
        "pathlib",
        "typing",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    """Self-check: seal a batch, prove each leaf, verify, tamper, fail."""
    pins = ["sha256:" + f"{i:064x}" for i in range(1, 6)]
    batch = seal_batch(pins, first_seq=1)
    assert batch.depth == 3  # 5 leaves -> depth 3
    for i, pin in enumerate(pins):
        proof = batch.proof(i)
        assert verify_proof(pin, proof, batch.root) is True
    # Tamper: wrong leaf must not verify.
    bad_proof = batch.proof(0)
    assert verify_proof(pins[1], bad_proof, batch.root) is False
    # Single-leaf batch.
    single = seal_batch(pins[:1])
    assert single.depth == 0
    assert verify_proof(pins[0], single.proof(0), single.root) is True
    assert stdlib_only()
    print("seal-merkle-batch OK: seal, prove, verify, pins, stdlib")


if __name__ == "__main__":
    main()
