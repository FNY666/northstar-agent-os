"""Consistent hashing — Dynamo-ring node bookkeeping.

Research note (consistent hashing): Dynamo's partition ring places each
node at several *virtual* positions (``sha256(node_id, i)`` for
``i in range(replicas * weight)``) on a 2^256 ring. A key is owned by the
first live node clockwise from ``sha256(key)``; ``preference-list`` replicas
are the next distinct nodes clockwise. Adding or removing a node only
remaps the key ranges it owns — K/N keys move on average, never a full
reshuffle. The same construction underlies Chord, Kademlia buckets, and
most client-side partitioners.

This module takes that intersection for a deterministic single-host
ledger:

* **Ring as frozen facts**: ``add()`` mints a frozen ``NodeRecord`` with
  its deterministic virtual-node positions; ``remove()`` books a frozen
  ``RemoveRecord``. Node positions are derived, never assigned by the
  caller.
* **Reads are data**: ``locate(key, seq)`` returns a frozen
  ``LocateReport`` (owner + preference list) as a pure view — validated
  seq, no audit row, no state change.
* **Weighted nodes**: ``add()`` takes a ``weight`` (positive int); the
  node's virtual-node count is ``replicas * weight``, so a weight-3 node
  owns ~3x the key space of a weight-1 node.

House rules: frozen dataclasses, caller-supplied strictly-increasing int
seqs (failed mutations consume their seq), RLock guarding, fail-closed
taxonomy, stdlib-only, sha256 digest pins over canonical payloads,
``audit.ndjson/1`` events.

Honest boundary: this module books *declared* ring membership and
*deterministic* key placement. It runs no gossip, probes no liveness, and
cannot promise that a key's recorded owner actually holds the key — the
host wires the frozen records to its own membership and storage planes
and treats the ledger as the placement authority. GIGO on node ids and
keys: the ledger pins what the host declares.
"""

from __future__ import annotations

import bisect
import hashlib
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Tuple

#: Version pin for this module's record shape.
CONSISTENT_HASHING_VERSION = "consistent-hashing.v1"

#: Schema pin carried by records and audit events.
CONSISTENT_HASHING_SCHEMA = "northstar.consistent-hashing.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Digest prefix for pins.
_DIGEST_PREFIX = "sha256:"

#: Ring modulus: 2^256 (sha256 output space).
_RING_BITS = 256
_RING_MOD = 1 << _RING_BITS

#: Bookkeeping bounds (not protocol limits).
MAX_NODE_ID_LEN = 256
MAX_KEY_LEN = 1024
MAX_WEIGHT = 1024
MAX_VNODES_PER_NODE = 1_048_576  # 1024 * 1024, a sane cap

#: Audit event kinds.
KIND_NODE_ADDED = "consistent.node-added"
KIND_NODE_REMOVED = "consistent.node-removed"
KIND_REJECTED = "consistent.rejected"
_KINDS = frozenset({KIND_NODE_ADDED, KIND_NODE_REMOVED, KIND_REJECTED})


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class ConsistentHashingError(Exception):
    """Base error for the consistent-hashing ledger."""


class BadNodeError(ConsistentHashingError):
    """Malformed node id or weight."""


class DuplicateNodeError(ConsistentHashingError):
    """Node id already present on the ring."""


class UnknownNodeError(ConsistentHashingError):
    """Node id not present on the ring."""


class BadKeyError(ConsistentHashingError):
    """Malformed key."""


class EmptyRingError(ConsistentHashingError):
    """Lookup attempted on a ring with no nodes."""


class SeqOrderError(ConsistentHashingError):
    """Seq did not strictly increase."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _check_seq(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise SeqOrderError(f"{name} must be a non-negative int")
    return value


def _check_node_id(value: Any, name: str = "node_id") -> str:
    if not isinstance(value, str) or not value or len(value) > MAX_NODE_ID_LEN:
        raise BadNodeError(f"{name} must be a non-empty str <= {MAX_NODE_ID_LEN}")
    if any(c.isspace() for c in value):
        raise BadNodeError(f"{name} must not contain whitespace")
    return value


def _check_weight(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise BadNodeError("weight must be an int")
    if not 1 <= value <= MAX_WEIGHT:
        raise BadNodeError(f"weight must be in [1, {MAX_WEIGHT}]")
    return value


def _check_replicas(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise BadNodeError("replicas must be an int")
    if not 1 <= value <= MAX_VNODES_PER_NODE:
        raise BadNodeError(f"replicas must be in [1, {MAX_VNODES_PER_NODE}]")
    return value


def _check_key(value: Any) -> str:
    if not isinstance(value, str) or not value or len(value) > MAX_KEY_LEN:
        raise BadKeyError(f"key must be a non-empty str <= {MAX_KEY_LEN}")
    return value


def _canonical(value: Any) -> bytes:
    """Canonical encoding for digest pins (stdlib-only)."""
    try:
        from northstar_agent_runtime import canonical_json  # type: ignore

        payload = canonical_json.dumps(value)
        return payload.encode("utf-8")
    except Exception:
        import json

        payload = json.dumps(value, sort_keys=True, separators=(",", ":"))
        return payload.encode("utf-8")


def _pin(*parts: Any) -> str:
    digest = hashlib.sha256(
        _canonical([CONSISTENT_HASHING_VERSION, *parts])
    ).hexdigest()
    return f"{_DIGEST_PREFIX}{digest}"


def _hash_key(key: str) -> int:
    return int.from_bytes(hashlib.sha256(key.encode("utf-8")).digest(), "big")


def _vnode_position(node_id: str, index: int) -> int:
    return int.from_bytes(
        hashlib.sha256(f"{node_id}#{index}".encode("utf-8")).digest(), "big"
    )


# ---------------------------------------------------------------------------
# Frozen records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class NodeRecord:
    """One node added to the ring (frozen). Positions are derived, not chosen."""

    node_id: str
    weight: int
    vnode_positions: Tuple[int, ...]
    seq: int
    digest: str
    schema: str = CONSISTENT_HASHING_SCHEMA

    def verify(self) -> bool:
        expected = _expected_vnodes(
            self.node_id, self.weight, len(self.vnode_positions)
        )
        return self.digest == _pin(
            "node", self.node_id, self.weight, expected, self.seq
        )


def _vn_count(record: NodeRecord) -> int:
    return len(record.vnode_positions)


@dataclass(frozen=True)
class RemoveRecord:
    """One node removed from the ring (frozen)."""

    node_id: str
    seq: int
    digest: str
    schema: str = CONSISTENT_HASHING_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin("remove", self.node_id, self.seq)


@dataclass(frozen=True)
class LocateReport:
    """One key-placement read (frozen). A pure view as data."""

    key: str
    owner: str
    preference_list: Tuple[str, ...]
    at_seq: int
    digest: str
    schema: str = CONSISTENT_HASHING_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "locate",
            self.key,
            self.owner,
            list(self.preference_list),
            self.at_seq,
        )


def _expected_vnodes(node_id: str, weight: int, count: int) -> Tuple[int, ...]:
    return tuple(sorted(_vnode_position(node_id, i) for i in range(count)))


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------


def consistent_hashing_audit_event(
    kind: str, detail: Mapping[str, Any], seq: int
) -> Dict[str, Any]:
    """Shape an ``audit.ndjson/1`` record for the ring ledger."""
    if kind not in _KINDS:
        raise ConsistentHashingError(f"unknown audit kind: {kind!r}")
    _check_seq(seq, "seq")
    if not isinstance(detail, Mapping):
        raise ConsistentHashingError("detail must be a mapping")
    # Only ids, pins, and small ints cross the audit boundary.
    banned = {"key", "node_positions", "positions", "payload"}
    if any(k in detail for k in banned):
        raise ConsistentHashingError("detail carries banned keys")
    return {
        "schema": AUDIT_SCHEMA,
        "kind": kind,
        "module": CONSISTENT_HASHING_VERSION,
        "detail": dict(detail),
        "seq": seq,
    }


# ---------------------------------------------------------------------------
# The ledger
# ---------------------------------------------------------------------------


class ConsistentHashing:
    """Deterministic Dynamo-ring membership ledger.

    All state mutations take a caller-supplied ``seq`` (monotonic logical
    time); no wall-clock is read anywhere. Failed mutations consume their
    seq (fail-closed ledger position).
    """

    def __init__(self, replicas: int = 100) -> None:
        self._replicas = _check_replicas(replicas)
        self._lock = threading.RLock()
        self._nodes: Dict[str, NodeRecord] = {}
        # Ring: sorted list of (position, node_id).
        self._ring: List[Tuple[int, str]] = []
        self._audit: List[Dict[str, Any]] = []
        self._last_seq = -1

    # -- internals ------------------------------------------------------

    def _bump(self, seq: int) -> int:
        _check_seq(seq, "seq")
        if seq <= self._last_seq:
            raise SeqOrderError(
                f"seq {seq} did not strictly increase (last {self._last_seq})"
            )
        self._last_seq = seq
        return seq

    def _reject(self, seq: int, reason: str, error: Exception) -> None:
        self._audit.append(
            consistent_hashing_audit_event(
                KIND_REJECTED, {"reason": reason}, seq
            )
        )
        raise error

    def _record_node(self, node_id: str, weight: int, seq: int) -> NodeRecord:
        vnodes = _expected_vnodes(node_id, weight, self._replicas * weight)
        return NodeRecord(
            node_id=node_id,
            weight=weight,
            vnode_positions=vnodes,
            seq=seq,
            digest=_pin("node", node_id, weight, vnodes, seq),
        )

    # -- public API -----------------------------------------------------

    def add(self, node_id: str, seq: int, weight: int = 1) -> NodeRecord:
        """Add ``node_id`` to the ring with ``weight`` virtual-node share."""
        with self._lock:
            self._bump(seq)
            try:
                node_id = _check_node_id(node_id)
                weight = _check_weight(weight)
            except ConsistentHashingError as e:
                self._reject(seq, "bad-node", e)
            if node_id in self._nodes:
                self._reject(
                    seq,
                    "duplicate-node",
                    DuplicateNodeError(f"node already on ring: {node_id!r}"),
                )
            record = self._record_node(node_id, weight, seq)
            self._nodes[node_id] = record
            for pos in record.vnode_positions:
                bisect.insort(self._ring, (pos, node_id))
            self._audit.append(
                consistent_hashing_audit_event(
                    KIND_NODE_ADDED,
                    {
                        "node_id": node_id,
                        "weight": weight,
                        "vnode_count": len(record.vnode_positions),
                    },
                    seq,
                )
            )
            return record

    def remove(self, node_id: str, seq: int) -> RemoveRecord:
        """Remove ``node_id`` from the ring. The id may be re-added later."""
        with self._lock:
            self._bump(seq)
            try:
                node_id = _check_node_id(node_id)
            except ConsistentHashingError as e:
                self._reject(seq, "bad-node", e)
            if node_id not in self._nodes:
                self._reject(
                    seq,
                    "unknown-node",
                    UnknownNodeError(f"node not on ring: {node_id!r}"),
                )
            record = self._nodes.pop(node_id)
            self._ring = [
                (pos, nid) for (pos, nid) in self._ring if nid != node_id
            ]
            self._audit.append(
                consistent_hashing_audit_event(
                    KIND_NODE_REMOVED,
                    {
                        "node_id": node_id,
                        "released_vnodes": len(record.vnode_positions),
                    },
                    seq,
                )
            )
            return RemoveRecord(
                node_id=node_id,
                seq=seq,
                digest=_pin("remove", node_id, seq),
            )

    def locate(self, key: str, seq: int, replicas: int = 1) -> LocateReport:
        """Place ``key`` on the ring (pure read view; no audit row).

        Returns the clockwise owner plus a preference list of the next
        ``replicas - 1`` distinct nodes clockwise (Dynamo preference list).
        """
        with self._lock:
            _check_seq(seq, "at_seq")
            try:
                key = _check_key(key)
                _check_replicas(replicas)
            except ConsistentHashingError as e:
                # Read views validate but never burn a seq position.
                raise e
            if not self._ring:
                raise EmptyRingError("cannot locate: ring is empty")
            point = _hash_key(key)
            idx = bisect.bisect_left(self._ring, (point, ""))
            if idx == len(self._ring):
                idx = 0  # wrap: the first vnode owns the tail
            preference: List[str] = []
            seen = set()
            i = idx
            while len(preference) < min(replicas, len(self._nodes)):
                nid = self._ring[i % len(self._ring)][1]
                if nid not in seen:
                    seen.add(nid)
                    preference.append(nid)
                i += 1
            owner = preference[0]
            return LocateReport(
                key=key,
                owner=owner,
                preference_list=tuple(preference),
                at_seq=seq,
                digest=_pin("locate", key, owner, list(preference), seq),
            )

    # -- pure views -----------------------------------------------------

    def node(self, node_id: str) -> NodeRecord:
        with self._lock:
            record = self._nodes.get(node_id)
            if record is None:
                raise UnknownNodeError(f"node not on ring: {node_id!r}")
            return record

    def node_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._nodes))

    def ring_size(self) -> int:
        """Number of virtual nodes currently on the ring (pure read)."""
        with self._lock:
            return len(self._ring)

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "nodes": len(self._nodes),
                "vnodes": len(self._ring),
                "replicas": self._replicas,
                "audit_events": len(self._audit),
                "last_seq": self._last_seq,
            }

    def audit_log(self) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._audit)


def main() -> None:
    """Self-check: add, locate, remove, views, audit."""
    ring = ConsistentHashing(replicas=8)
    rec = ring.add("a", 1)
    assert rec.verify() and rec.node_id == "a"
    assert ring.node_ids() == ("a",)
    rep = ring.locate("user-1", 2)
    assert rep.verify() and rep.owner == "a" and rep.preference_list == ("a",)
    ring.add("b", 3)
    rep2 = ring.locate("user-1", 4)
    assert rep2.verify() and rep2.owner in ("a", "b")
    ring.remove("b", 5)
    assert ring.node_ids() == ("a",)
    kinds = [e["kind"] for e in ring.audit_log()]
    assert KIND_NODE_ADDED in kinds and KIND_NODE_REMOVED in kinds
    assert consistent_hashing_audit_event(
        KIND_NODE_ADDED, {"node_id": "a"}, 6
    )["schema"] == AUDIT_SCHEMA
    print("consistent-hashing OK: add, locate, remove, views, audit")


if __name__ == "__main__":
    main()
