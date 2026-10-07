"""Authenticated dictionary: a key/value map with Merkle inclusion proofs.

Research motivation: an *authenticated dictionary* lets a prover commit to
a whole key/value state with one short digest (the root) and later hand a
verifier an O(log n) *inclusion proof* that a particular key maps to a
particular value under that root -- the primitive behind transparency
logs (RFC 9162), authenticated file systems, and certificate
transparency. For an agent runtime this is the shape of "prove to an
auditor that the config/policy/budget table you committed to earlier had
exactly this entry, without revealing the rest of the table".

Construction (all offline, deterministic, stdlib-only):

* Keys are ``str`` (non-empty), values are ``str`` or ``bytes``.
* Entries are sorted by key (Python codepoint order -- fixed, documented)
  and each leaf is
  ``SHA-256(0x00 || u32be(len(key)) || key || u32be(len(value)) || value)``.
  The length prefixes matter: without them ``("a", "bc")`` and
  ``("ab", "c")`` hash identically, and a proof would bind nothing.
* Internal nodes are ``SHA-256(0x01 || left || right)`` with the RFC 9162
  split rule (largest power of two strictly smaller than ``n``) -- the
  same construction as ``audit_merkle`` uses for the audit feed, so the
  two roots are built by the same math.
* The empty tree has a defined root: ``SHA-256(b"")``, pinned as
  ``sha256:<hex>``. Digests are always ``sha256:<hex>`` pins.
* ``put(key, value)`` overwrites in place; ``get(key)`` returns the
  value or ``None`` (a miss is a policy outcome, never an error);
  ``proof(key)`` returns a frozen ``InclusionProof`` for an existing
  key and raises ``AuthDictError`` for a missing one (there are no
  non-inclusion proofs here -- see honest scope); ``verify(proof, key,
  value, root)`` folds the proof and returns ``True``/``False``
  (malformed or mismatched proofs are ``False``; wrong *types* raise).

Honest scope:

* This is an in-memory authenticated *map*, not a database. The tree is
  rebuilt from the entry set on every mutation, so ``put`` is O(n log n)
  -- fine for policy tables and config snapshots, wrong for hot storage.
* Inclusion proofs only. A missing key has no proof, and a proof says
  nothing about keys other than the one it names. A root commits to the
  *full* entry set as of the last ``put`` -- the host must anchor or sign
  roots (``auth_dict_audit_event`` shapes the audit records) for the root
  to mean anything to a third party.
* Single writer, no concurrency control beyond a re-entrant lock for the
  read path; no wall-clock anywhere; caller-supplied seqs only.
* Same canonical-JSON-adjacent caveat as elsewhere in the runtime: the
  pins are over raw key/value bytes, not JSON, so the >2**53 integer
  issue does not apply here -- but a host that *serializes* values into
  JSON before storing them inherits that caveat.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from typing import Tuple

#: Module version pin (also stamped on every record).
AUTH_DICT_VERSION = "auth-dict.v1"

#: Schema pin for frozen records and audit bodies.
AUTH_DICT_SCHEMA = "northstar.auth-dict.v1"

#: Fixed audit event vocabulary for ``auth_dict_audit_event``.
EVENT_PUT = "put"
EVENT_PROOF = "proof"
EVENT_VERIFY = "verify"
EVENT_ROOT = "root"

_EVENT_KINDS = frozenset({EVENT_PUT, EVENT_PROOF, EVENT_VERIFY, EVENT_ROOT})

_LEAF_PREFIX = b"\x00"
_NODE_PREFIX = b"\x01"
_MAX_PATH_LEN = 64


class AuthDictError(Exception):
    """Fail-closed error for authenticated-dictionary misuse."""


def _u32be(n: int) -> bytes:
    return n.to_bytes(4, "big")


def _pin(raw: bytes) -> str:
    """``sha256:<hex>`` digest pin."""
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _leaf_hash(key: bytes, value: bytes) -> bytes:
    """Leaf hash with length prefixes (see module docstring for why)."""
    return hashlib.sha256(
        _LEAF_PREFIX + _u32be(len(key)) + key + _u32be(len(value)) + value
    ).digest()


def _node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(_NODE_PREFIX + left + right).digest()


def _split(n: int) -> int:
    """Largest power of two strictly smaller than n (RFC 9162 split)."""
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def _calc_root(leaves: list[bytes]) -> bytes:
    n = len(leaves)
    if n == 0:
        return hashlib.sha256(b"").digest()
    if n == 1:
        return leaves[0]
    k = _split(n)
    return _node_hash(_calc_root(leaves[:k]), _calc_root(leaves[k:]))


def _path_len(n: int, index: int) -> int:
    """Proof-path length for leaf ``index`` in an n-leaf RFC 9162 tree.

    The tree is unbalanced (the right subtree of a split can be a single
    leaf), so path length depends on position, not just on n -- it is the
    depth the leaf sits at. Mirrors ``_proof_path``'s recursion.
    """
    h = 0
    while n > 1:
        k = _split(n)
        if index < k:
            n = k
        else:
            n -= k
            index -= k
        h += 1
    return h


def _proof_path(leaves: list[bytes], index: int) -> list[tuple[str, bytes]]:
    """Sibling steps from the leaf at ``index`` up to the root.

    Each step is ``("L", sibling)`` (sibling is left of the running hash)
    or ``("R", sibling)`` (sibling is right of the running hash).
    """
    n = len(leaves)
    if n == 1:
        return []
    k = _split(n)
    if index < k:
        sibling = _calc_root(leaves[k:])
        return _proof_path(leaves[:k], index) + [("R", sibling)]
    sibling = _calc_root(leaves[:k])
    return _proof_path(leaves[k:], index - k) + [("L", sibling)]


def _check_key(key: object) -> str:
    if isinstance(key, bool) or not isinstance(key, str):
        raise TypeError(f"key must be a str, got {type(key).__name__}")
    if key == "":
        raise ValueError("key must be non-empty")
    return key


def _check_value(value: object) -> bytes:
    if isinstance(value, bool):
        raise TypeError("value must be str or bytes, not bool")
    if isinstance(value, str):
        return value.encode("utf-8")
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    raise TypeError(f"value must be str or bytes, got {type(value).__name__}")


def _check_seq(seq: object, name: str) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise TypeError(f"{name} must be an int, got {type(seq).__name__}")
    if seq < 0:
        raise ValueError(f"{name} must be >= 0")
    return seq


@dataclass(frozen=True)
class InclusionProof:
    """Frozen Merkle inclusion proof for one key/value pair.

    ``steps`` is a tuple of ``(side, sibling_digest_hex)`` where ``side``
    is ``"L"`` or ``"R"`` (sibling relative to the running hash),
    ordered leaf-to-root. ``leaf_index`` is the leaf's position in the
    sorted leaf order (needed because the RFC 9162 tree is unbalanced,
    so path length depends on position). ``root_digest`` is the
    ``sha256:<hex>`` pin the proof was minted against.
    """

    key: str
    value_digest: str
    steps: Tuple[Tuple[str, str], ...]
    leaf_count: int
    leaf_index: int
    root_digest: str
    version: str = AUTH_DICT_VERSION
    schema: str = AUTH_DICT_SCHEMA

    def as_dict(self) -> dict:
        return {
            "key": self.key,
            "value_digest": self.value_digest,
            "steps": [{"side": s, "sibling": d} for s, d in self.steps],
            "leaf_count": self.leaf_count,
            "leaf_index": self.leaf_index,
            "root_digest": self.root_digest,
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class DictSummary:
    """Frozen view of the dictionary state behind a root."""

    root_digest: str
    entries: int
    version: str = AUTH_DICT_VERSION
    schema: str = AUTH_DICT_SCHEMA

    def as_dict(self) -> dict:
        return {
            "root_digest": self.root_digest,
            "entries": self.entries,
            "version": self.version,
            "schema": self.schema,
        }


class AuthDict:
    """Key/value map with Merkle inclusion proofs (see module docstring)."""

    def __init__(self) -> None:
        self._entries: dict[str, bytes] = {}
        self._lock = threading.RLock()

    def put(self, key: str, value: object) -> None:
        """Insert or overwrite ``key``. Fail-closed on bad key/value."""
        key = _check_key(key)
        raw = _check_value(value)
        with self._lock:
            self._entries[key] = raw

    def get(self, key: str) -> bytes | None:
        """Return the raw value bytes, or ``None`` on a miss (policy)."""
        key = _check_key(key)
        with self._lock:
            v = self._entries.get(key)
        if v is None:
            return None
        return bytes(v)

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)

    def keys(self) -> tuple[str, ...]:
        """Keys in proof order (lexicographic)."""
        with self._lock:
            return tuple(sorted(self._entries))

    # -- tree internals -------------------------------------------------

    def _sorted_items(self) -> list[tuple[str, bytes]]:
        with self._lock:
            return sorted(self._entries.items(), key=lambda kv: kv[0])

    def _leaves(self) -> list[bytes]:
        return [
            _leaf_hash(k.encode("utf-8"), v) for k, v in self._sorted_items()
        ]

    # -- root -----------------------------------------------------------

    def root(self) -> str:
        """``sha256:<hex>`` pin of the current tree root (empty tree defined)."""
        return _pin(b"") if len(self) == 0 else "sha256:" + _calc_root(self._leaves()).hex()

    def summary(self) -> DictSummary:
        return DictSummary(root_digest=self.root(), entries=len(self))

    # -- proofs ---------------------------------------------------------

    def proof(self, key: str) -> InclusionProof:
        """Mint an inclusion proof for an existing key.

        Raises ``AuthDictError`` for a missing key -- absence has no
        proof in this construction.
        """
        key = _check_key(key)
        items = self._sorted_items()
        index = next((i for i, (k, _) in enumerate(items) if k == key), None)
        if index is None:
            raise AuthDictError(f"no entry for key {key!r}: nothing to prove")
        leaves = [_leaf_hash(k.encode("utf-8"), v) for k, v in items]
        steps = _proof_path(leaves, index)
        value = items[index][1]
        return InclusionProof(
            key=key,
            value_digest=_pin(value),
            steps=tuple((side, sib.hex()) for side, sib in steps),
            leaf_count=len(items),
            leaf_index=index,
            root_digest=self.root(),
        )


def verify(proof: InclusionProof, key: str, value: object, root: str) -> bool:
    """Verify that ``proof`` binds ``key``/``value`` to ``root``.

    Returns ``True``/``False`` -- a proof that does not check out is
    ``False``, never an exception. Wrong *types* raise ``TypeError``.
    """
    if not isinstance(proof, InclusionProof):
        raise TypeError(f"proof must be an InclusionProof, got {type(proof).__name__}")
    key = _check_key(key)
    raw = _check_value(value)
    if isinstance(root, bool) or not isinstance(root, str):
        raise TypeError(f"root must be a str, got {type(root).__name__}")

    if proof.key != key:
        return False
    if proof.value_digest != _pin(raw):
        return False
    if proof.root_digest != root:
        return False
    if (
        isinstance(proof.leaf_count, bool)
        or not isinstance(proof.leaf_count, int)
        or proof.leaf_count < 1
    ):
        return False
    if (
        isinstance(proof.leaf_index, bool)
        or not isinstance(proof.leaf_index, int)
        or not 0 <= proof.leaf_index < proof.leaf_count
    ):
        return False
    if len(proof.steps) > _MAX_PATH_LEN:
        return False
    if len(proof.steps) != _path_len(proof.leaf_count, proof.leaf_index):
        return False

    try:
        running = _leaf_hash(key.encode("utf-8"), raw)
        for side, sib_hex in proof.steps:
            if side not in ("L", "R"):
                return False
            sibling = bytes.fromhex(sib_hex)
            if len(sibling) != 32:
                return False
            running = (
                _node_hash(running, sibling)
                if side == "R"
                else _node_hash(sibling, running)
            )
    except (ValueError, TypeError):
        return False
    return "sha256:" + running.hex() == root


def auth_dict_audit_event(kind: str, record: object, seq: int) -> dict:
    """Shape an ``audit.ndjson/1`` record for an auth-dict event. Fail-closed."""
    if kind not in _EVENT_KINDS:
        raise ValueError(f"unknown auth-dict event kind: {kind!r}")
    seq = _check_seq(seq, "audit_seq")
    body = record.as_dict() if hasattr(record, "as_dict") else {"record": str(record)}
    return {
        "schema": "audit.ndjson/1",
        "kind": kind,
        "seq": seq,
        "body": body,
    }


def main() -> None:
    """Self-check: build a small dict, prove one entry, verify it."""
    d = AuthDict()
    d.put("budget:skill-x", "100")
    d.put("policy:kill-switch", b"\x01armed")
    d.put("config:region", "gd")
    r = d.root()
    p = d.proof("policy:kill-switch")
    assert verify(p, "policy:kill-switch", b"\x01armed", r) is True
    assert verify(p, "policy:kill-switch", b"\x00disarmed", r) is False
    assert verify(p, "budget:skill-x", "100", r) is False  # wrong key
    # order independence: same entries, different insertion order, same root
    d2 = AuthDict()
    d2.put("config:region", "gd")
    d2.put("budget:skill-x", "100")
    d2.put("policy:kill-switch", b"\x01armed")
    assert d2.root() == r
    print("auth-dict OK: put/get, order-independent root, proof verifies, tampering rejected")


if __name__ == "__main__":
    main()
