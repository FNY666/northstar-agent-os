"""Consistent hashing: deterministic key-to-node routing for sharded work.

Research note: consistent hashing (Karger et al., 1997) maps keys to a
ring shared with nodes so that adding or removing a node reassigns only
``~K/N`` keys instead of ``~K`` — the property that makes it safe to grow
a shard fleet, a cache tier, or an agent worker pool without mass key
movement. Here the ring is a routing instrument for the host's own
placement decisions (which worker owns this conversation shard, which
cache node holds this memory segment); it does not move data itself.

* **Virtual nodes** — each physical node owns ``replicas`` points on the
  ring. More virtual nodes per node smooths the load distribution and
  reduces the standard deviation of per-node key counts; the trade-off
  is memory for the ring table and a longer ring walk on updates.
* **Deterministic** — ring placement is ``sha256``-derived; the same
  ``(node_id, replicas)`` set always builds the same ring, so routing is
  replayable and two hosts agree without coordination. No randomness, no
  wall-clock.
* **Fail-closed** — routing an empty ring raises (a key must never be
  "routed" to nowhere by defaulting to a node); duplicate adds and
  unknown removes raise; non-string keys/nodes raise rather than hash
  implicitly.

Honest scope: this module routes *keys to names* — it cannot verify the
named node is alive, healthy, or the true owner. "``get_node`` returned
``worker-3``" means "the ring places this key at worker-3", never
"worker-3 is reachable". Liveness, ownership enforcement, and data
migration are the host's job; the module only guarantees the placement
rule is stable, deterministic, and minimally disruptive under membership
changes.
"""

from __future__ import annotations

import hashlib
from bisect import bisect_left
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

#: Module version.
CONSISTENT_HASH_VERSION = "consistent-hash.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.consistent-hash.v1"

#: Hash domain separator so ring points cannot collide with other digests.
_HASH_DOMAIN = b"northstar.consistent-hash.v1\x00"


class ConsistentHashError(Exception):
    """Base error for consistent-hash ring misuse."""


class EmptyRingError(ConsistentHashError):
    """Raised when routing a key against a ring with no nodes."""


def _ring_point(token: str) -> int:
    """Deterministic ring position for a token (node replica or key)."""
    digest = hashlib.sha256(_HASH_DOMAIN + token.encode("utf-8")).digest()
    return int.from_bytes(digest, "big")


@dataclass(frozen=True)
class RingSnapshot:
    """Immutable view of the ring: node -> virtual-point count."""

    node_counts: Tuple[Tuple[str, int], ...]
    replicas: int
    total_points: int

    def as_dict(self) -> dict:
        return {
            "schema": SCHEMA_PIN,
            "node_counts": [
                {"node_id": node_id, "points": count}
                for node_id, count in self.node_counts
            ],
            "replicas": self.replicas,
            "total_points": self.total_points,
        }


class ConsistentHash:
    """Consistent-hash ring with virtual nodes.

    ``replicas`` is the number of virtual points per physical node and is
    fixed at construction: changing it later would silently re-place
    every key, which is exactly the mass-movement this module exists to
    avoid.
    """

    def __init__(self, replicas: int = 100) -> None:
        if isinstance(replicas, bool) or not isinstance(replicas, int):
            raise TypeError("replicas must be an int")
        if replicas < 1:
            raise ValueError("replicas must be >= 1")
        self._replicas = replicas
        # Sorted list of (point, node_id) pairs; the ring.
        self._ring: List[Tuple[int, str]] = []
        # Physical node -> its sorted virtual points (for clean removal).
        self._node_points: Dict[str, List[int]] = {}

    @property
    def replicas(self) -> int:
        return self._replicas

    def add_node(self, node_id: str) -> int:
        """Add a physical node; returns the number of virtual points added.

        Raises :class:`ConsistentHashError` on a duplicate node (adding
        the same node twice is a caller bug, not a mergeable update) and
        ``TypeError``/``ValueError`` on a malformed ``node_id``.
        """
        if not isinstance(node_id, str):
            raise TypeError("node_id must be a str")
        if not node_id:
            raise ValueError("node_id must be non-empty")
        if node_id in self._node_points:
            raise ConsistentHashError(f"node already on the ring: {node_id!r}")
        points = sorted(
            _ring_point(f"{node_id}\x00{i}") for i in range(self._replicas)
        )
        for point in points:
            idx = bisect_left(self._ring, (point, node_id))
            # Tie-break on node_id is impossible in practice (sha256), but
            # the insert position is deterministic either way.
            self._ring.insert(idx, (point, node_id))
        self._node_points[node_id] = points
        return len(points)

    def remove_node(self, node_id: str) -> int:
        """Remove a physical node and all its virtual points.

        Returns the number of virtual points removed. Raises ``KeyError``
        for an unknown node — silently ignoring an unknown remove would
        hide a host's bookkeeping bug about who owns the fleet.
        """
        if not isinstance(node_id, str):
            raise TypeError("node_id must be a str")
        if node_id not in self._node_points:
            raise KeyError(f"unknown node: {node_id!r}")
        remove = set(self._node_points.pop(node_id))
        self._ring = [
            (point, owner) for point, owner in self._ring
            if point not in remove
        ]
        return len(remove)

    def nodes(self) -> Tuple[str, ...]:
        """Physical node ids, in first-added order."""
        return tuple(self._node_points)

    def snapshot(self) -> RingSnapshot:
        """Immutable summary of the current ring."""
        return RingSnapshot(
            node_counts=tuple(
                (node_id, len(self._node_points[node_id]))
                for node_id in self.nodes()
            ),
            replicas=self._replicas,
            total_points=len(self._ring),
        )

    def get_node(self, key: str) -> str:
        """Return the node id that owns ``key`` (first ring point clockwise).

        The lookup walks clockwise from the key's hash point and wraps to
        the start of the ring — every key has an owner as long as the ring
        is non-empty. Raises :class:`EmptyRingError` on an empty ring and
        ``TypeError`` on a non-string key.
        """
        if not isinstance(key, str):
            raise TypeError("key must be a str")
        if not self._ring:
            raise EmptyRingError("cannot route: the ring has no nodes")
        point = _ring_point(key)
        idx = bisect_left(self._ring, (point, ""))
        if idx == len(self._ring):
            idx = 0  # wrap: clockwise from the key's point
        return self._ring[idx][1]

    def get_nodes(self, key: str, count: int) -> Tuple[str, ...]:
        """Return ``count`` distinct owners for ``key``, clockwise.

        The replication/failover set for a key: the primary followed by
        the next distinct physical nodes clockwise. Useful for the host to
        keep ``count`` copies. Raises ``ValueError`` if ``count`` exceeds
        the physical node count; ``EmptyRingError`` on an empty ring.
        """
        if isinstance(count, bool) or not isinstance(count, int):
            raise TypeError("count must be an int")
        if count < 1:
            raise ValueError("count must be >= 1")
        if not self._ring:
            raise EmptyRingError("cannot route: the ring has no nodes")
        if count > len(self._node_points):
            raise ValueError(
                f"count {count} exceeds physical node count "
                f"{len(self._node_points)}"
            )
        point = _ring_point(key)
        idx = bisect_left(self._ring, (point, ""))
        owners: List[str] = []
        seen = set()
        for offset in range(len(self._ring)):
            owner = self._ring[(idx + offset) % len(self._ring)][1]
            if owner not in seen:
                seen.add(owner)
                owners.append(owner)
                if len(owners) == count:
                    break
        return tuple(owners)

    def __len__(self) -> int:
        return len(self._node_points)


def consistent_hash_audit_event(
    action: str, ring: ConsistentHash, node_id: Optional[str], seq: int
) -> dict:
    """Shape an ``audit.ndjson/1``-style record for a ring membership change."""
    if action not in ("node-added", "node-removed"):
        raise ValueError(f"unknown action: {action!r}")
    if not isinstance(node_id, str) or not node_id:
        raise ValueError("node_id must be a non-empty str")
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise ValueError("seq must be a non-negative int")
    if not isinstance(ring, ConsistentHash):
        raise TypeError("ring must be a ConsistentHash")
    return {
        "schema": SCHEMA_PIN,
        "event": "consistent-hash." + action,
        "node_id": node_id,
        "node_count": len(ring),
        "total_points": ring.snapshot().total_points,
        "audit_seq": seq,
    }


def main() -> None:
    ring = ConsistentHash(replicas=16)
    ring.add_node("worker-1")
    ring.add_node("worker-2")
    ring.add_node("worker-3")
    keys = [f"conversation-{i}" for i in range(200)]
    owners = {ring.get_node(k) for k in keys}
    assert owners == {"worker-1", "worker-2", "worker-3"}, owners
    # Minimal disruption: removing one node only moves its keys.
    before = {k: ring.get_node(k) for k in keys}
    ring.remove_node("worker-2")
    after = {k: ring.get_node(k) for k in keys}
    moved = [k for k in keys if before[k] != after[k]]
    assert moved, "removal must move some keys"
    assert all(before[k] == "worker-2" for k in moved), "only the removed node's keys move"
    print(
        "consistent-hash OK: 200 keys on 3 nodes, "
        f"{len(moved)} moved on node removal (removed node's keys only)"
    )


if __name__ == "__main__":
    main()
