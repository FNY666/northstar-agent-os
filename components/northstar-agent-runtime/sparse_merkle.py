"""Sparse Merkle tree over a 256-bit key space, for key-value proofs.

A sparse Merkle tree is a binary Merkle tree of fixed depth (here 256)
where most leaves are empty. Because the tree is *sparse*, only
non-default nodes are stored, so a tree holding a handful of keys costs
O(k * depth) memory instead of O(2**depth).

What this gives the runtime:

* **Inclusion proof**: O(256) hashes proving "key K maps to value V under
  root R" — a verifier holding a trusted root can check one key without
  the whole tree.
* **Non-inclusion proof**: the same shape proves "key K is *absent* under
  root R" — the leaf on K's path hashes to the default empty leaf. This
  is what a plain hash map cannot do, and it is the reason this module
  exists: absence must be provable, not just asserted.

Design decisions, stated plainly:

* **Key space**: the caller supplies a ``str``/``bytes`` key; the tree
  path is ``SHA-256`` of the canonical key bytes (str is UTF-8 encoded).
  Keys are therefore uniformly distributed over the 256-bit space and
  the tree stays balanced by construction. Ordering is *not* preserved:
  this is an authenticated map, not an ordered index (see
  ``btree_index`` for ordering).
* **Domain separation** (three prefixes, so no two node kinds collide):
  leaf ``= SHA-256(0x00 || value)``,
  internal ``= SHA-256(0x01 || left || right)``,
  default empty leaf ``= SHA-256(0x02)``.
  The default leaf can never equal a real leaf, so a present key holding
  any value — even the empty value — is distinguishable from an absent
  key. Internal defaults are precomputed per level:
  ``default[256] = DEFAULT_LEAF``,
  ``default[d] = node_hash(default[d+1], default[d+1])``.
* **Fail-closed**: keys must be non-empty ``str``/``bytes``; values must
  be ``str``/``bytes``; anything else raises ``TypeError``/``ValueError``
  at the boundary. A proof with the wrong sibling count, a bad hash
  length, or a non-``SparseMerkleProof`` input is rejected, never
  "verified as false and shrugged at".
* **No wall-clock, no randomness, stdlib only** (``hashlib``,
  ``hmac``, ``dataclasses``, ``typing``). Everything is deterministic:
  two trees receiving the same updates in any order converge to the
  same root (updates to distinct keys commute).

Honest scope: this is an in-memory authenticated key-value store, not a
database. A proof is only meaningful against a root the verifier already
trusts — a bare root does not stop the tree owner from presenting a
different tree (roots must be anchored or signed, e.g. via the audit
chain or ``TreeHead.sign``-style machinery). ``get`` returns canonical
``bytes`` (str values are UTF-8 encoded on the way in). There is no
persistence here; pair with the durable audit writer for crash recovery.
"""
from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

#: Module version pin.
SPARSE_MERKLE_VERSION = "sparse-merkle.v1"

#: Schema pin used in audit events and proof documents.
SCHEMA_PIN = "northstar.sparse-merkle.v1"

#: Fixed tree depth: the key space is 2**256.
DEPTH = 256

#: Hash output size in bytes.
_HASH_SIZE = 32

_LEAF_PREFIX = b"\x00"
_NODE_PREFIX = b"\x01"
_EMPTY_PREFIX = b"\x02"


def _leaf_hash(value: bytes) -> bytes:
    """Hash of a present leaf holding ``value``."""
    return hashlib.sha256(_LEAF_PREFIX + value).digest()


def _node_hash(left: bytes, right: bytes) -> bytes:
    """Hash of an internal node."""
    return hashlib.sha256(_NODE_PREFIX + left + right).digest()


#: The hash standing in for "no key on this path". Domain-separated so it
#: can never equal a real leaf hash.
_DEFAULT_LEAF = hashlib.sha256(_EMPTY_PREFIX).digest()

#: _DEFAULTS[d] is the hash of the default (all-empty) subtree at depth d,
#: where d = 256 is a leaf and d = 0 is the tree root.
_DEFAULTS: Tuple[bytes, ...] = ()


def _build_defaults() -> Tuple[bytes, ...]:
    defaults = [_DEFAULT_LEAF] * (DEPTH + 1)
    for d in range(DEPTH - 1, -1, -1):
        defaults[d] = _node_hash(defaults[d + 1], defaults[d + 1])
    return tuple(defaults)


_DEFAULTS = _build_defaults()

#: Root of the empty tree.
EMPTY_ROOT = _DEFAULTS[0]


class SparseMerkleError(Exception):
    """Base error for sparse-merkle misuse."""


def _check_key(key: Any) -> bytes:
    if isinstance(key, str):
        key = key.encode("utf-8")
    if not isinstance(key, bytes):
        raise TypeError(
            f"key must be str or bytes, got {type(key).__name__}")
    if len(key) == 0:
        raise ValueError("key must not be empty")
    return key


def _check_value(value: Any) -> bytes:
    if isinstance(value, str):
        value = value.encode("utf-8")
    if not isinstance(value, bytes):
        raise TypeError(
            f"value must be str or bytes, got {type(value).__name__}")
    return value


def _check_seq(seq: Any, name: str) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise TypeError(f"{name} must be an int, got {type(seq).__name__}")
    if seq < 0:
        raise ValueError(f"{name} must be >= 0")
    return seq


def _path_for(key_bytes: bytes) -> bytes:
    """The 32-byte tree path for canonical key bytes."""
    return hashlib.sha256(key_bytes).digest()


def _sibling_count_ok(proof: "SparseMerkleProof") -> bool:
    return (
        len(proof.siblings) == DEPTH
        and all(isinstance(s, bytes) and len(s) == _HASH_SIZE
                for s in proof.siblings)
    )


@dataclass(frozen=True)
class SparseMerkleProof:
    """A proof of inclusion *or* non-inclusion for one key.

    ``value`` is ``None`` for a non-inclusion proof. ``siblings[i]`` is
    the sibling hash at tree level ``256 - i`` — i.e. ``siblings[0]`` is
    the sibling of the leaf, ``siblings[255]`` the sibling just below the
    root. The root is recomputed by hashing from the leaf upward; the
    proof verifies iff the recomputed root equals ``root``.
    """
    key: bytes
    path: bytes
    value: Optional[bytes]
    siblings: Tuple[bytes, ...]
    root: bytes
    schema: str = SCHEMA_PIN

    def __post_init__(self) -> None:
        if not isinstance(self.key, bytes) or len(self.key) == 0:
            raise TypeError("proof key must be non-empty bytes")
        if not isinstance(self.path, bytes) or len(self.path) != _HASH_SIZE:
            raise TypeError("proof path must be 32 bytes")
        if self.value is not None and not isinstance(self.value, bytes):
            raise TypeError("proof value must be bytes or None")
        if not _sibling_count_ok(self):
            raise ValueError(
                f"proof needs exactly {DEPTH} 32-byte siblings")
        if not isinstance(self.root, bytes) or len(self.root) != _HASH_SIZE:
            raise TypeError("proof root must be 32 bytes")
        if self.schema != SCHEMA_PIN:
            raise ValueError(f"unknown schema pin: {self.schema!r}")
        if _path_for(self.key) != self.path:
            raise ValueError("proof path does not match proof key")

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": self.schema,
            "module": SPARSE_MERKLE_VERSION,
            "key_hex": self.key.hex(),
            "path_hex": self.path.hex(),
            "value_hex": self.value.hex() if self.value is not None else None,
            "inclusion": self.value is not None,
            "siblings_hex": [s.hex() for s in self.siblings],
            "root_hex": self.root.hex(),
        }


def verify_proof(proof: SparseMerkleProof) -> bool:
    """Recompute the root from ``proof``; True iff it matches.

    A True result for a proof with ``value=None`` is a verified proof of
    *non-inclusion*: the key is absent under that root.
    """
    if not isinstance(proof, SparseMerkleProof):
        raise TypeError(
            f"expected SparseMerkleProof, got {type(proof).__name__}")
    current = _DEFAULT_LEAF if proof.value is None else _leaf_hash(proof.value)
    index = int.from_bytes(proof.path, "big")
    for level in range(DEPTH, 0, -1):
        sibling = proof.siblings[DEPTH - level]
        if index & 1 == 0:
            current = _node_hash(current, sibling)
        else:
            current = _node_hash(sibling, current)
        index >>= 1
    return hmac.compare_digest(current, proof.root)


def verify_against(root: bytes, proof: SparseMerkleProof) -> bool:
    """True iff ``proof`` is internally consistent *and* pins ``root``.

    Use this when the trusted root comes from somewhere else (an anchored
    tree head, a signed checkpoint): the proof must both recompute
    cleanly and land on the root you already trust.
    """
    if not isinstance(root, bytes) or len(root) != _HASH_SIZE:
        raise TypeError("root must be 32 bytes")
    if not isinstance(proof, SparseMerkleProof):
        raise TypeError(
            f"expected SparseMerkleProof, got {type(proof).__name__}")
    if not hmac.compare_digest(proof.root, root):
        return False
    return verify_proof(proof)


class SparseMerkleTree:
    """In-memory sparse Merkle tree over SHA-256 key paths."""

    def __init__(self) -> None:
        # (level, index) -> hash, stored only when != default at that level.
        self._nodes: Dict[Tuple[int, int], bytes] = {}
        # 32-byte path -> canonical value bytes.
        self._values: Dict[bytes, bytes] = {}

    def _node_at(self, level: int, index: int) -> bytes:
        return self._nodes.get((level, index), _DEFAULTS[level])

    def _set_node(self, level: int, index: int, digest: bytes) -> None:
        if digest == _DEFAULTS[level]:
            self._nodes.pop((level, index), None)
        else:
            self._nodes[(level, index)] = digest

    def update(self, key: Any, value: Any) -> bytes:
        """Set ``key`` to ``value``; returns the new root hash."""
        key_bytes = _check_key(key)
        value_bytes = _check_value(value)
        path = _path_for(key_bytes)
        index = int.from_bytes(path, "big")
        self._set_node(DEPTH, index, _leaf_hash(value_bytes))
        for level in range(DEPTH, 0, -1):
            if index & 1 == 0:
                left = self._node_at(level, index)
                right = self._node_at(level, index | 1)
            else:
                left = self._node_at(level, index & ~1)
                right = self._node_at(level, index)
            self._set_node(level - 1, index >> 1, _node_hash(left, right))
            index >>= 1
        self._values[path] = value_bytes
        return self.root()

    def delete(self, key: Any) -> bool:
        """Remove ``key``; True iff the key was present.

        Deletion restores the default subtree along the key's path, so a
        later ``proof(key)`` is a verifiable proof of non-inclusion.
        """
        key_bytes = _check_key(key)
        path = _path_for(key_bytes)
        if path not in self._values:
            return False
        del self._values[path]
        index = int.from_bytes(path, "big")
        self._set_node(DEPTH, index, _DEFAULT_LEAF)
        for level in range(DEPTH, 0, -1):
            if index & 1 == 0:
                left = self._node_at(level, index)
                right = self._node_at(level, index | 1)
            else:
                left = self._node_at(level, index & ~1)
                right = self._node_at(level, index)
            self._set_node(level - 1, index >> 1, _node_hash(left, right))
            index >>= 1
        return True

    def get(self, key: Any) -> Optional[bytes]:
        """Canonical value bytes for ``key``, or None if absent."""
        key_bytes = _check_key(key)
        return self._values.get(_path_for(key_bytes))

    def contains(self, key: Any) -> bool:
        """True iff ``key`` is present."""
        return self.get(key) is not None

    def root(self) -> bytes:
        """Current 32-byte root hash."""
        return self._node_at(0, 0)

    def root_hex(self) -> str:
        """Current root as 64 hex chars."""
        return self.root().hex()

    def __len__(self) -> int:
        return len(self._values)

    def proof(self, key: Any) -> SparseMerkleProof:
        """Mint an inclusion or non-inclusion proof for ``key``."""
        key_bytes = _check_key(key)
        path = _path_for(key_bytes)
        index = int.from_bytes(path, "big")
        siblings = []
        for level in range(DEPTH, 0, -1):
            siblings.append(self._node_at(level, index ^ 1))
            index >>= 1
        return SparseMerkleProof(
            key=key_bytes,
            path=path,
            value=self._values.get(path),
            siblings=tuple(siblings),
            root=self.root(),
        )


def sparse_merkle_audit_event(kind: str, seq: int,
                              key: Any = None,
                              root: Optional[bytes] = None,
                              verified: Optional[bool] = None) -> Dict[str, Any]:
    """Shape an ``audit.ndjson/1`` record for sparse-merkle decisions."""
    if kind not in ("updated", "deleted", "proof-generated",
                    "proof-verified"):
        raise ValueError(f"unknown kind: {kind!r}")
    _check_seq(seq, "seq")
    event: Dict[str, Any] = {
        "schema": "audit.ndjson/1",
        "module": SCHEMA_PIN,
        "kind": kind,
        "audit_seq": seq,
    }
    if key is not None:
        key_bytes = _check_key(key)
        event["key_sha256"] = hashlib.sha256(key_bytes).hexdigest()
    if root is not None:
        if not isinstance(root, bytes) or len(root) != _HASH_SIZE:
            raise TypeError("root must be 32 bytes")
        event["root_hex"] = root.hex()
    if verified is not None:
        if not isinstance(verified, bool):
            raise TypeError("verified must be bool")
        event["verified"] = verified
    return event


def main() -> None:
    tree = SparseMerkleTree()
    assert tree.root() == EMPTY_ROOT, "empty tree must pin the default root"
    tree.update("alice", "wallets:3")
    tree.update(b"bob", b"wallets:7")
    assert tree.get("alice") == b"wallets:3"
    assert tree.get("carol") is None

    inc = tree.proof("alice")
    assert verify_proof(inc), "inclusion proof must verify"
    assert inc.value == b"wallets:3"

    non = tree.proof("carol")
    assert non.value is None, "absent key mints non-inclusion proof"
    assert verify_proof(non), "non-inclusion proof must verify"

    tree.delete("alice")
    gone = tree.proof("alice")
    assert gone.value is None and verify_proof(gone)

    # Order independence: distinct-key updates commute to the same root.
    t2 = SparseMerkleTree()
    t2.update(b"bob", b"wallets:7")
    assert t2.root() == tree.root(), "roots must agree after same key set"

    print("sparse-merkle OK: update, delete, inclusion/non-inclusion proofs")


if __name__ == "__main__":
    main()
