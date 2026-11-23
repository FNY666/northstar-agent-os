"""Transparency log: append-only Merkle log in the Certificate Transparency style.

A ``TransparencyLog`` is an ordered, append-only sequence of entries with a
single evolving head (the tree root).  Hosts can hand out two kinds of proof:

* ``inclusion_proof(index)`` — Merkle audit path showing the entry at
  ``index`` is committed to the current head.
* ``consistency_proof(old_size, new_size)`` — proof that the tree of
  ``new_size`` leaves is a valid append-only extension of the tree of
  ``old_size`` leaves (RFC 6962 section 2.1.2 construction).

Tree shape (RFC 6962): leaf hash ``SHA-256(0x00 || data)``; internal node
``SHA-256(0x01 || left || right)``; for ``n > 1`` leaves the tree splits at
``k``, the largest power of two smaller than ``n`` (``[0,k)`` left,
``[k,n)`` right).  The empty tree's root is ``SHA-256(b"")``.

House style: no wall-clock, fail-closed, stdlib-only, deterministic, frozen
records, version/schema pins, ``main()`` self-check.

Honest scope: single-node in-memory bookkeeping, not a distributed CT log —
no Signed Tree Heads, no gossip, no external witnesses.  ``verify_*`` checks
byte-level consistency of proofs, never "the fleet saw it".  Entries are
host-supplied; a proof binds the entry bytes, not their truth.  A
``ConsistencyProof`` for equal sizes is degenerate (empty proof; the check
is ``old_root == new_root``).

Version pin: transparency-log.v1
Schema pin: northstar.transparency-log.v1
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Sequence

TRANSPARENCY_LOG_VERSION = "transparency-log.v1"
SCHEMA_PIN = "northstar.transparency-log.v1"

#: Root of the empty tree: SHA-256 of the empty string (RFC 6962).
EMPTY_ROOT = hashlib.sha256(b"").digest()

_AUDIT_KINDS = ("appended", "inclusion-proved", "consistency-proved")


class TransparencyLogError(Exception):
    """Raised for structural misuse (bad index, bad sizes, empty log)."""


def _leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()


def _node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _split(n: int) -> tuple[int, int]:
    """Split n leaves at k, the largest power of two smaller than n."""
    k = 1 << ((n - 1).bit_length() - 1)
    return k, n - k


def _coerce_entry(entry) -> bytes:
    if isinstance(entry, bool):
        raise TypeError("entry must be str or bytes, got bool")
    if isinstance(entry, str):
        return entry.encode("utf-8")
    if isinstance(entry, bytes):
        return entry
    raise TypeError(f"entry must be str or bytes, got {type(entry).__name__}")


def _require_index(name: str, value) -> int:
    if isinstance(value, bool):
        raise TypeError(f"{name} must be an int, got bool")
    if not isinstance(value, int):
        raise TypeError(f"{name} must be an int, got {type(value).__name__}")
    if value < 0:
        raise ValueError(f"{name} must be non-negative")
    return value


def _require_seq(seq) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise TypeError("seq must be an int")
    if seq < 0:
        raise ValueError("seq must be non-negative")
    return seq


def _require_root(name: str, value) -> bytes:
    if not isinstance(value, bytes):
        raise TypeError(f"{name} must be bytes")
    if len(value) != 32:
        raise ValueError(f"{name} must be a 32-byte digest")
    return value


@dataclass(frozen=True)
class LogEntry:
    """Record minted at append time."""

    index: int
    entry_digest: str  # "sha256:<hex>" over the raw entry bytes
    leaf_hash: bytes  # domain-separated leaf hash

    def as_dict(self) -> dict:
        return {
            "index": self.index,
            "entry_digest": self.entry_digest,
            "leaf_hash": self.leaf_hash.hex(),
            "schema": SCHEMA_PIN,
        }


@dataclass(frozen=True)
class ProofStep:
    """One sibling hash on the path from leaf to root."""

    sibling_hash: bytes
    sibling_is_left: bool

    def as_dict(self) -> dict:
        return {
            "sibling_hash": self.sibling_hash.hex(),
            "sibling_is_left": self.sibling_is_left,
        }


@dataclass(frozen=True)
class InclusionProof:
    """Merkle audit path for one leaf against a tree head."""

    index: int
    tree_size: int
    steps: tuple[ProofStep, ...]
    root: bytes  # head this proof was generated against

    def as_dict(self) -> dict:
        return {
            "index": self.index,
            "tree_size": self.tree_size,
            "steps": [s.as_dict() for s in self.steps],
            "root": self.root.hex(),
            "schema": SCHEMA_PIN,
        }


@dataclass(frozen=True)
class ConsistencyProof:
    """Proof that the new_size tree extends the old_size tree."""

    old_size: int
    new_size: int
    hashes: tuple[bytes, ...]

    def as_dict(self) -> dict:
        return {
            "old_size": self.old_size,
            "new_size": self.new_size,
            "hashes": [h.hex() for h in self.hashes],
            "schema": SCHEMA_PIN,
        }


def _audit_path(leaves: Sequence[bytes], index: int, n: int, offset: int,
                root_fn) -> list[ProofStep]:
    """Sibling hashes from the leaf at ``index`` up to the root of [offset, offset+n)."""
    if n == 1:
        return []
    k, _ = _split(n)
    if index < k:
        path = _audit_path(leaves, index, k, offset, root_fn)
        path.append(ProofStep(root_fn(offset + k, n - k), False))
    else:
        path = _audit_path(leaves, index - k, n - k, offset + k, root_fn)
        path.append(ProofStep(root_fn(offset, k), True))
    return path


def _consistency_hashes(m: int, n: int, offset: int, root_fn) -> list[bytes]:
    """Proof hashes showing tree(offset:offset+n) extends tree(offset:offset+m).

    Mirrors RFC 6962 SUBPROOF: base case emits the old subtree root; the
    verifier consumes hashes in the same order.
    """
    if m == n:
        return [root_fn(offset, n)]
    k, _ = _split(n)
    if m <= k:
        return _consistency_hashes(m, k, offset, root_fn) + [root_fn(offset + k, n - k)]
    return _consistency_hashes(m - k, n - k, offset + k, root_fn) + [root_fn(offset, k)]


def _verify_consistency_hashes(m: int, n: int, hashes: list[bytes]):
    """Derive (old_root, new_root) from proof hashes; returns ((old, new), rest)."""
    if m == n:
        first, rest = hashes[0], hashes[1:]
        return (first, first), rest
    k, _ = _split(n)
    if m <= k:
        (old_root, left_root), rest = _verify_consistency_hashes(m, k, hashes)
        right_root, rest = rest[0], rest[1:]
        return (old_root, _node_hash(left_root, right_root)), rest
    (old_right, new_right), rest = _verify_consistency_hashes(m - k, n - k, hashes)
    left_root, rest = rest[0], rest[1:]
    return (
        _node_hash(left_root, old_right),
        _node_hash(left_root, new_right),
    ), rest


def verify_inclusion(entry, proof: InclusionProof, expected_root: bytes) -> bool:
    """True iff ``entry`` is committed to ``expected_root`` via ``proof``."""
    data = _coerce_entry(entry)
    if not isinstance(proof, InclusionProof):
        raise TypeError("proof must be an InclusionProof")
    _require_root("expected_root", expected_root)
    acc = _leaf_hash(data)
    for step in proof.steps:
        if not isinstance(step, ProofStep):
            raise TypeError("proof steps must be ProofStep records")
        if step.sibling_is_left:
            acc = _node_hash(step.sibling_hash, acc)
        else:
            acc = _node_hash(acc, step.sibling_hash)
    return acc == expected_root


def verify_consistency(old_root: bytes, old_size: int, new_root: bytes,
                       new_size: int, hashes: Sequence[bytes]) -> bool:
    """True iff the proof shows the new tree extends the old tree.

    Type misuse raises; cryptographic mismatch (or malformed proof bytes)
    returns False.
    """
    _require_root("old_root", old_root)
    _require_root("new_root", new_root)
    old_size = _require_index("old_size", old_size)
    new_size = _require_index("new_size", new_size)
    if old_size < 1:
        raise TransparencyLogError("old_size must be >= 1")
    if new_size < old_size:
        raise TransparencyLogError("new_size must be >= old_size")
    if not isinstance(hashes, Sequence):
        raise TypeError("hashes must be a sequence of bytes")
    for h in hashes:
        if not isinstance(h, bytes):
            raise TypeError("proof hashes must be bytes")
    if old_size == new_size:
        return len(hashes) == 0 and old_root == new_root
    if any(len(h) != 32 for h in hashes):
        return False
    try:
        (derived_old, derived_new), rest = _verify_consistency_hashes(
            old_size, new_size, list(hashes)
        )
    except IndexError:
        return False
    return len(rest) == 0 and derived_old == old_root and derived_new == new_root


def transparency_log_audit_event(kind: str, seq: int) -> dict:
    """Audit-shaped record for a transparency-log observation."""
    if kind not in _AUDIT_KINDS:
        raise ValueError(f"unknown kind {kind!r}")
    _require_seq(seq)
    return {
        "event": "transparency-log",
        "outcome": kind,
        "audit_seq": seq,
        "schema": "audit.ndjson/1",
    }


class TransparencyLog:
    """In-memory append-only Merkle log (Certificate Transparency style)."""

    def __init__(self) -> None:
        self._leaves: list[bytes] = []
        self._root_cache: dict[tuple[int, int], bytes] = {}

    def append(self, entry) -> LogEntry:
        data = _coerce_entry(entry)
        index = len(self._leaves)
        self._leaves.append(data)
        return LogEntry(
            index=index,
            entry_digest="sha256:" + hashlib.sha256(data).hexdigest(),
            leaf_hash=_leaf_hash(data),
        )

    def size(self) -> int:
        return len(self._leaves)

    def root(self) -> bytes:
        return self._root(0, len(self._leaves))

    def _root(self, offset: int, n: int) -> bytes:
        key = (offset, n)
        cached = self._root_cache.get(key)
        if cached is not None:
            return cached
        if n == 0:
            result = EMPTY_ROOT
        elif n == 1:
            result = _leaf_hash(self._leaves[offset])
        else:
            k, _ = _split(n)
            result = _node_hash(self._root(offset, k), self._root(offset + k, n - k))
        self._root_cache[key] = result
        return result

    def inclusion_proof(self, index: int) -> InclusionProof:
        index = _require_index("index", index)
        n = len(self._leaves)
        if n == 0:
            raise TransparencyLogError("cannot prove inclusion in an empty log")
        if index >= n:
            raise TransparencyLogError(f"index {index} out of range for size {n}")
        steps = _audit_path(self._leaves, index, n, 0, self._root)
        return InclusionProof(index=index, tree_size=n, steps=tuple(steps), root=self.root())

    def consistency_proof(self, old_size: int, new_size: int) -> ConsistencyProof:
        old_size = _require_index("old_size", old_size)
        new_size = _require_index("new_size", new_size)
        if old_size < 1:
            raise TransparencyLogError("old_size must be >= 1")
        if new_size < old_size:
            raise TransparencyLogError("new_size must be >= old_size")
        if new_size > len(self._leaves):
            raise TransparencyLogError(
                f"new_size {new_size} beyond log size {len(self._leaves)}"
            )
        if old_size == new_size:
            return ConsistencyProof(old_size=old_size, new_size=new_size, hashes=())
        hashes = _consistency_hashes(old_size, new_size, 0, self._root)
        return ConsistencyProof(old_size=old_size, new_size=new_size, hashes=tuple(hashes))


def main() -> None:
    log = TransparencyLog()
    assert log.size() == 0
    assert log.root() == EMPTY_ROOT
    entries = [f"entry-{i}".encode() for i in range(7)]
    for e in entries:
        log.append(e)
    head = log.root()
    for i, e in enumerate(entries):
        proof = log.inclusion_proof(i)
        assert verify_inclusion(e, proof, head), f"inclusion failed at {i}"
    for m in range(1, 7):
        cp = log.consistency_proof(m, 7)
        prefix = TransparencyLog()
        for e in entries[:m]:
            prefix.append(e)
        assert verify_consistency(prefix.root(), m, head, 7, cp.hashes), f"consistency {m}->7"
    assert transparency_log_audit_event("appended", 0)["schema"] == "audit.ndjson/1"
    print("transparency-log OK: append, inclusion, consistency")


if __name__ == "__main__":
    main()
