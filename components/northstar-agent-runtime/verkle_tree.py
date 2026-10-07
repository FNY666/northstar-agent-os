"""Verkle tree: authenticated key-value store with vector commitments.

Research motivation: Verkle trees are Ethereum's planned state-tree
upgrade. Where a Merkle tree hashes each node's children, a Verkle tree
holds a *vector commitment* (a KZG polynomial commitment in production)
over them. Commitments are constant-size and support small multiproofs:
one proof can cover many keys with far less bandwidth than a Merkle
multiproof. This module is the network-free, deterministic interface
half: a k-ary trie over SHA-256 key paths where every node carries a
vector commitment over its children, with inclusion *and* non-inclusion
proofs.

Public API:

- ``vc_commit(slot_pins)`` / ``vc_open(commitment, index, slot_pin)`` /
  ``vc_verify(commitment, index, slot_pin, opening)`` -- simulated vector
  commitment. ``vc_commit`` pins the full ordered vector (position
  binding: any change at any index changes the commitment). ``vc_open``
  mints a deterministic opening binding ``(commitment, index, slot_pin)``;
  ``vc_verify`` recomputes and compares in constant time.
- ``VerkleTree(branching=16, depth=64)`` -- mutable trie. ``put(key,
  value)`` inserts or replaces; ``get(key)`` returns the value or
  ``None``; ``root()`` returns the ``sha256:`` root commitment;
  ``proof(key)`` returns a frozen ``VerkleProof`` for present *or* absent
  keys (non-inclusion is provable: the leaf slot pins ``EMPTY_PIN``).
- ``VerkleProof`` -- frozen record: per-level ``ProofLevel`` openings
  (commitment, index, child pin, opening), the normalized key, a
  ``present`` flag, the value digest, and the root. ``verify(key,
  value=None)`` replays the chain; ``as_dict()`` carries the schema pin.
- ``verify_proof(proof, key, value=None)`` -- module-level verifier.
- ``verkle_audit_event(kind, seq, key=None, present=None)`` -- shapes
  ``audit.ndjson/1`` records (``put`` / ``proof-generated`` /
  ``proof-verified`` / ``rejected``). Keys are audit-pinned by digest,
  never logged raw.

Key paths: ``nibbles = sha256("verkle-tree.v1/key-path" || key)``; the
first ``depth`` nibbles address one slot per level. ``depth`` is bounded
(1..64); two distinct keys sharing a ``depth``-nibble prefix raise
``KeyPathCollisionError`` fail-closed instead of silently overwriting --
a bounded-depth trie cannot address both, so the collision is surfaced,
not hidden.

Honest scope:

- The vector commitment is *simulated* with SHA-256, not KZG over
  BLS12-381. The simulation preserves the interface properties the tree
  depends on (position binding, opening soundness) but provides no
  hiding (it is deterministic), no aggregation of many openings into one
  constant-size multiproof (each opening is its own pin), and no
  elliptic-curve security argument. A proof here is a chain of
  per-level openings whose length grows with ``depth``.
- This is an in-memory authenticated dictionary, not a database: no
  disk I/O, no persistence (the host owns durability), no concurrency
  control. ``root()`` recomputes commitments on demand.
- Proofs authenticate *this tree's* state against a trusted root. They
  cannot prove the host did not withhold keys (the root must be anchored
  externally) and they bind key+value digests, not value semantics.
- Values must be JCS-canonicalizable (str/int/float/bool/None/list/dict
  with str keys; NaN/inf and non-str dict keys rejected). The shared
  canonicalizer caveat applies: integer values above 2**53 may lose
  precision (see ``consensus_interface``); hosts pinning large ints
  should use the fixed-width hex pattern from ``secure_aggregation``.
"""

from __future__ import annotations

import hashlib
import hmac
import math
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json, jcs_sha256_hex
except Exception:  # pragma: no cover - module must stay importable standalone
    import json as _json

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return _json.dumps(obj, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True).encode("utf-8")

    def jcs_sha256_hex(obj: Any) -> str:  # type: ignore[no-redef]
        return hashlib.sha256(jcs_canonical_json(obj)).hexdigest()


#: Version pin for this module's record shape.
VERKLE_TREE_VERSION = "verkle-tree.v1"

#: Schema pin carried by records and audit events.
SCHEMA_PIN = "northstar.verkle-tree.v1"

#: Pin used for an empty vector slot; also the non-inclusion witness.
EMPTY_PIN = "sha256:" + "00" * 32

#: Bounds for the trie shape parameters.
MIN_BRANCHING = 2
MAX_BRANCHING = 256
MIN_DEPTH = 1
MAX_DEPTH = 64  # nibbles of a SHA-256 hex digest

_TAG_VC_COMMIT = b"verkle-tree.v1/vc-commit\x00"
_TAG_VC_OPEN = b"verkle-tree.v1/vc-open\x00"
_TAG_ENTRY = b"verkle-tree.v1/entry\x00"
_TAG_KEY_PATH = b"verkle-tree.v1/key-path\x00"
_TAG_AUDIT_KEY = b"verkle-tree.v1/audit-key\x00"


class VerkleTreeError(Exception):
    """Base error for the verkle tree layer (programming errors)."""


class KeyPathCollisionError(VerkleTreeError):
    """Two distinct keys share a depth-bounded path prefix.

    Raised fail-closed by ``put`` (and defensively by ``proof``) instead
    of silently overwriting one key with the other.
    """


def _is_pin(value: object) -> bool:
    """Non-raising check for a ``sha256:<64 hex>`` pin."""
    if not isinstance(value, str) or len(value) != 71:
        return False
    if not value.startswith("sha256:"):
        return False
    try:
        int(value[7:], 16)
    except ValueError:
        return False
    return True


def _check_pin(value: object, name: str) -> str:
    """Validate a ``sha256:<64 hex>`` digest pin (fail-closed)."""
    if not _is_pin(value):
        raise ValueError(f"{name} must be a 'sha256:'<64 hex> pin")
    return value  # type: ignore[return-value]


def _check_branching(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(
            f"branching must be int, got {type(value).__name__}")
    if not MIN_BRANCHING <= value <= MAX_BRANCHING:
        raise ValueError(
            f"branching must be {MIN_BRANCHING}..{MAX_BRANCHING}, got {value}")
    return value


def _check_depth(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(
            f"depth must be int, got {type(value).__name__}")
    if not MIN_DEPTH <= value <= MAX_DEPTH:
        raise ValueError(
            f"depth must be {MIN_DEPTH}..{MAX_DEPTH}, got {value}")
    return value


def _check_key(key: object) -> bytes:
    """Normalize a key to bytes: non-empty str (utf-8) or bytes."""
    if isinstance(key, bool):
        raise TypeError("key must be str or bytes, not bool")
    if isinstance(key, str):
        raw = key.encode("utf-8")
    elif isinstance(key, (bytes, bytearray)):
        raw = bytes(key)
    else:
        raise TypeError(
            f"key must be str or bytes, got {type(key).__name__}")
    if not raw:
        raise ValueError("key must be non-empty")
    return raw


def _check_value(value: Any) -> None:
    """Fail-closed check that a value is JCS-canonicalizable."""
    if value is None or isinstance(value, (str, bool)):
        return
    if isinstance(value, int):
        return
    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            raise ValueError("value must not be NaN or infinite")
        return
    if isinstance(value, list):
        for item in value:
            _check_value(item)
        return
    if isinstance(value, dict):
        for k, v in value.items():
            if not isinstance(k, str):
                raise TypeError(
                    "value dict keys must be str, "
                    f"got {type(k).__name__}")
            _check_value(v)
        return
    raise TypeError(
        f"value of type {type(value).__name__} is not canonicalizable")


def _check_seq(value: object, name: str = "seq") -> int:
    """Validate a caller-supplied audit seq: int, not bool, >= 0."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be int, got {type(value).__name__}")
    if value < 0:
        raise ValueError(f"{name} must be >= 0, got {value}")
    return value


def _check_index(value: object, name: str = "index") -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be int, got {type(value).__name__}")
    if value < 0:
        raise ValueError(f"{name} must be >= 0, got {value}")
    return value


# ---------------------------------------------------------------------------
# Simulated vector commitment
# ---------------------------------------------------------------------------

def vc_commit(slot_pins: List[str]) -> str:
    """Commit to an ordered vector of slot pins (simulated KZG).

    Position binding: the commitment pins the full ordered vector, so any
    change at any index changes the commitment. Deterministic; provides
    no hiding.
    """
    if not isinstance(slot_pins, (list, tuple)) or not slot_pins:
        raise ValueError("vc_commit needs a non-empty vector of slot pins")
    body = _TAG_VC_COMMIT + len(slot_pins).to_bytes(4, "big")
    for pin in slot_pins:
        _check_pin(pin, "slot_pin")
        body += bytes.fromhex(pin[7:])
    return "sha256:" + hashlib.sha256(body).hexdigest()


def vc_open(commitment: str, index: int, slot_pin: str) -> str:
    """Mint a deterministic opening binding (commitment, index, slot_pin)."""
    _check_pin(commitment, "commitment")
    _check_index(index)
    _check_pin(slot_pin, "slot_pin")
    body = (_TAG_VC_OPEN + bytes.fromhex(commitment[7:])
            + index.to_bytes(8, "big") + bytes.fromhex(slot_pin[7:]))
    return "sha256:" + hashlib.sha256(body).hexdigest()


def vc_verify(commitment: str, index: int, slot_pin: str,
              opening: str) -> bool:
    """Verify an opening; ``False`` (never raise) on any mismatch."""
    if not (_is_pin(commitment) and _is_pin(slot_pin)
            and _is_pin(opening)):
        return False
    if isinstance(index, bool) or not isinstance(index, int) or index < 0:
        return False
    expected = vc_open(commitment, index, slot_pin)
    return hmac.compare_digest(expected, opening)


# ---------------------------------------------------------------------------
# Proof records
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ProofLevel:
    """One level of a verkle proof: the opening of a child slot."""
    commitment: str   # node commitment at this level
    index: int        # slot index taken at this level
    child_pin: str    # what the slot commits to (child node or entry pin)
    opening: str      # vc opening binding (commitment, index, child_pin)

    def __post_init__(self) -> None:
        _check_pin(self.commitment, "commitment")
        _check_index(self.index)
        _check_pin(self.child_pin, "child_pin")
        _check_pin(self.opening, "opening")


def _check_hex64(value: object, name: str) -> str:
    if not isinstance(value, str) or len(value) != 64:
        raise ValueError(f"{name} must be 64 hex chars")
    try:
        int(value, 16)
    except ValueError:
        raise ValueError(f"{name} must be 64 hex chars")
    return value


@dataclass(frozen=True)
class VerkleProof:
    """Frozen inclusion / non-inclusion proof for one key."""
    depth: int
    branching: int
    levels: Tuple[ProofLevel, ...]
    key: bytes
    present: bool
    value_digest: Optional[str]
    root: str

    def __post_init__(self) -> None:
        _check_depth(self.depth)
        _check_branching(self.branching)
        if not isinstance(self.levels, tuple) or not self.levels:
            raise TypeError("levels must be a non-empty tuple of ProofLevel")
        for lvl in self.levels:
            if not isinstance(lvl, ProofLevel):
                raise TypeError(
                    f"levels must hold ProofLevel, got {type(lvl).__name__}")
        if len(self.levels) != self.depth:
            raise ValueError(
                f"len(levels)={len(self.levels)} != depth={self.depth}")
        if not isinstance(self.key, bytes) or not self.key:
            raise TypeError("key must be non-empty bytes")
        if not isinstance(self.present, bool):
            raise TypeError("present must be bool")
        if self.value_digest is not None:
            _check_hex64(self.value_digest, "value_digest")
        if self.present and self.value_digest is None:
            raise ValueError("present proofs must carry a value_digest")
        if not self.present and self.value_digest is not None:
            raise ValueError("absent proofs must not carry a value_digest")
        _check_pin(self.root, "root")

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "version": VERKLE_TREE_VERSION,
            "depth": self.depth,
            "branching": self.branching,
            "key_hex": self.key.hex(),
            "present": self.present,
            "value_digest": self.value_digest,
            "root": self.root,
            "levels": [
                {"commitment": l.commitment, "index": l.index,
                 "child_pin": l.child_pin, "opening": l.opening}
                for l in self.levels
            ],
        }

    def verify(self, key: str | bytes, value: Any = None) -> bool:
        """Replay the proof chain against this proof's root.

        For present proofs a value is required and must reproduce the
        leaf entry pin. For absent proofs the value must be ``None`` and
        the leaf slot must pin ``EMPTY_PIN``. Returns ``False`` on any
        mismatch; raises ``TypeError``/``ValueError`` only for a malformed
        caller-supplied key (programmer error, not proof failure).
        """
        kb = _check_key(key)
        if kb != self.key:
            return False
        nibbles = _key_nibbles(kb, self.depth)
        if any(lvl.index != nib for lvl, nib in zip(self.levels, nibbles)):
            return False
        expected = self.root
        for lvl in self.levels:
            if not hmac.compare_digest(lvl.commitment, expected):
                return False
            if not vc_verify(lvl.commitment, lvl.index,
                             lvl.child_pin, lvl.opening):
                return False
            expected = lvl.child_pin
        last = self.levels[-1]
        if self.present:
            if value is None:
                return False
            try:
                _check_value(value)
            except (TypeError, ValueError):
                return False
            digest = jcs_sha256_hex(value)
            if not hmac.compare_digest(self.value_digest or "", digest):
                return False
            pin = _entry_pin(kb, digest)
            return hmac.compare_digest(pin, last.child_pin)
        if value is not None or self.value_digest is not None:
            return False
        return hmac.compare_digest(last.child_pin, EMPTY_PIN)


def verify_proof(proof: VerkleProof, key: str | bytes,
                 value: Any = None) -> bool:
    """Module-level verifier: ``False`` on any proof failure."""
    if not isinstance(proof, VerkleProof):
        raise TypeError(
            f"proof must be VerkleProof, got {type(proof).__name__}")
    return proof.verify(key, value)


# ---------------------------------------------------------------------------
# Internal trie nodes
# ---------------------------------------------------------------------------

def _key_nibbles(key: bytes, depth: int) -> Tuple[int, ...]:
    digest = hashlib.sha256(_TAG_KEY_PATH + key).hexdigest()
    return tuple(int(c, 16) for c in digest[:depth])


def _entry_pin(key: bytes, value_digest_hex: str) -> str:
    body = _TAG_ENTRY + key + b"\x00" + value_digest_hex.encode("utf-8")
    return "sha256:" + hashlib.sha256(body).hexdigest()


class _Entry:
    __slots__ = ("key", "value", "value_digest", "pin")

    def __init__(self, key: bytes, value: Any) -> None:
        self.key = key
        self.value = value
        self.value_digest = jcs_sha256_hex(value)
        self.pin = _entry_pin(key, self.value_digest)


class _Node:
    __slots__ = ("children", "entries")

    def __init__(self, branching: int) -> None:
        self.children: List[Optional[_Node]] = [None] * branching
        self.entries: Dict[int, _Entry] = {}


# ---------------------------------------------------------------------------
# The tree
# ---------------------------------------------------------------------------

class VerkleTree:
    """Authenticated key-value trie with vector commitments per node."""

    def __init__(self, branching: int = 16, depth: int = 64) -> None:
        self._branching = _check_branching(branching)
        self._depth = _check_depth(depth)
        self._root_node = _Node(self._branching)
        self._size = 0
        # Commitment of an all-empty subtree: identical at every level.
        self._empty_subtree = vc_commit([EMPTY_PIN] * self._branching)

    @property
    def branching(self) -> int:
        return self._branching

    @property
    def depth(self) -> int:
        return self._depth

    def __len__(self) -> int:
        return self._size

    # -- commitments ----------------------------------------------------

    def _node_commitment(self, node: _Node, level: int) -> str:
        if level == self._depth - 1:
            pins = [node.entries[i].pin if i in node.entries else EMPTY_PIN
                    for i in range(self._branching)]
        else:
            pins = [self._node_commitment(child, level + 1)
                    if child is not None else self._empty_subtree
                    for child in node.children]
        return vc_commit(pins)

    def root(self) -> str:
        """The ``sha256:`` root commitment of the current tree state."""
        return self._node_commitment(self._root_node, 0)

    # -- writes / reads --------------------------------------------------

    def put(self, key: str | bytes, value: Any) -> None:
        """Insert or replace ``key``; fail-closed on path collision."""
        kb = _check_key(key)
        _check_value(value)
        nibbles = _key_nibbles(kb, self._depth)
        node = self._root_node
        for level, nib in enumerate(nibbles):
            if level == self._depth - 1:
                existing = node.entries.get(nib)
                if existing is not None and existing.key != kb:
                    raise KeyPathCollisionError(
                        "two distinct keys share a depth-bounded path "
                        f"prefix (slot {nib} at depth {self._depth}); "
                        "increase depth")
                if existing is None:
                    self._size += 1
                node.entries[nib] = _Entry(kb, value)
                return
            child = node.children[nib]
            if child is None:
                child = _Node(self._branching)
                node.children[nib] = child
            node = child

    def get(self, key: str | bytes) -> Optional[Any]:
        """Return the stored value, or ``None`` when absent."""
        kb = _check_key(key)
        nibbles = _key_nibbles(kb, self._depth)
        node: Optional[_Node] = self._root_node
        for level, nib in enumerate(nibbles):
            if node is None:
                return None
            if level == self._depth - 1:
                entry = node.entries.get(nib)
                if entry is None or entry.key != kb:
                    return None
                return entry.value
            node = node.children[nib]
        return None  # pragma: no cover - loop always returns

    # -- proofs ----------------------------------------------------------

    def proof(self, key: str | bytes) -> VerkleProof:
        """Build an inclusion or non-inclusion proof for ``key``."""
        kb = _check_key(key)
        nibbles = _key_nibbles(kb, self._depth)
        levels: List[ProofLevel] = []
        node: Optional[_Node] = self._root_node
        present = False
        value_digest: Optional[str] = None
        for level, nib in enumerate(nibbles):
            commitment = (self._empty_subtree if node is None
                          else self._node_commitment(node, level))
            if level == self._depth - 1:
                entry = node.entries.get(nib) if node is not None else None
                if entry is not None and entry.key != kb:
                    raise KeyPathCollisionError(
                        "invariant: colliding entry on proof path")
                child_pin = entry.pin if entry is not None else EMPTY_PIN
                present = entry is not None
                value_digest = entry.value_digest if entry is not None else None
            else:
                child = node.children[nib] if node is not None else None
                child_pin = (self._node_commitment(child, level + 1)
                             if child is not None else self._empty_subtree)
            opening = vc_open(commitment, nib, child_pin)
            levels.append(ProofLevel(commitment=commitment, index=nib,
                                     child_pin=child_pin, opening=opening))
            if level < self._depth - 1:
                node = node.children[nib] if node is not None else None
        return VerkleProof(depth=self._depth, branching=self._branching,
                           levels=tuple(levels), key=kb, present=present,
                           value_digest=value_digest,
                           root=levels[0].commitment)


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------

def verkle_audit_event(kind: str, seq: int,
                       key: str | bytes | None = None,
                       present: bool | None = None) -> Dict[str, Any]:
    """Shape an ``audit.ndjson/1`` record for verkle tree decisions."""
    if kind not in ("put", "proof-generated", "proof-verified", "rejected"):
        raise ValueError(f"unknown kind: {kind!r}")
    _check_seq(seq, "seq")
    event: Dict[str, Any] = {
        "schema": "audit.ndjson/1",
        "module": SCHEMA_PIN,
        "kind": kind,
        "audit_seq": seq,
    }
    if key is not None:
        kb = _check_key(key)
        event["key_pin"] = ("sha256:" + hashlib.sha256(
            _TAG_AUDIT_KEY + kb).hexdigest())
    if present is not None:
        if not isinstance(present, bool):
            raise TypeError("present must be bool")
        event["present"] = present
    return event


def main() -> None:
    """Self-check: put/get, inclusion + non-inclusion proofs, root order."""
    tree = VerkleTree(branching=16, depth=8)
    assert tree.root() == VerkleTree(branching=16, depth=8).root()
    assert tree.root() != EMPTY_PIN
    assert len(tree) == 0

    tree.put("alice", {"balance": 100})
    tree.put(b"bob", [1, 2, 3])
    assert len(tree) == 2
    assert tree.get("alice") == {"balance": 100}
    assert tree.get(b"bob") == [1, 2, 3]
    assert tree.get("carol") is None

    inclusion = tree.proof("alice")
    assert inclusion.present
    assert len(inclusion.levels) == 8
    assert inclusion.verify("alice", {"balance": 100})
    assert verify_proof(inclusion, "alice", {"balance": 100})
    assert not inclusion.verify("alice", {"balance": 101})
    assert not inclusion.verify("mallory", {"balance": 100})

    absence = tree.proof("carol")
    assert not absence.present
    assert absence.verify("carol")
    assert not absence.verify("carol", 1)

    root = tree.root()
    assert inclusion.root == root == absence.root
    other = VerkleTree(branching=16, depth=8)
    other.put(b"bob", [1, 2, 3])
    other.put("alice", {"balance": 100})
    assert other.root() == root  # insertion order does not matter

    event = verkle_audit_event("put", 0, key="alice")
    assert event["schema"] == "audit.ndjson/1"
    assert event["module"] == SCHEMA_PIN
    print("verkle-tree OK: put/get, inclusion + non-inclusion proofs, "
          "order-independent root")


if __name__ == "__main__":
    main()
