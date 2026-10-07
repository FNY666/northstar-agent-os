"""CRDT interface: grow-only and PN counters for eventually consistent replicas.

Research note: Conflict-free Replicated Data Types (Shapiro et al. 2011)
give *convergent* state across replicas without coordination — every pair
of replicas can merge in any order and still converge to the same value.
That makes them a fit for the parts of an agent fleet that must stay
consistent across unreliable links: per-agent spend ledgers, probe-hit
counters, per-skill invocation tallies. The runtime already has
single-writer ledgers (:mod:`per_call_budget`, :mod:`dp_accountant`); this
module is the *multi-writer* counterpart for counters that several hosts
may advance independently.

* **GCounter** — grow-only counter. Each replica tracks its own
  increments; ``merge`` takes the per-replica *maximum*. Increments never
  decrease, so merge is commutative, associative, and idempotent: any
  merge order converges to the same total.
* **PNCounter** — positive-negative counter: two GCounters (``inc`` and
  ``dec``); ``value = inc.value - dec.value``. Supports decrement while
  staying convergent, because both halves only ever grow.
* **Immutable records** — counters are frozen dataclasses; every
  ``increment`` / ``decrement`` / ``merge`` returns a *new* counter.
  A replica that wants to keep its knowledge applies the result.
* **No wall-clock** — all sequencing is caller-supplied (``seq`` ints on
  audit events); replicas are identified by string ``replica_id``.
* **Fail-closed** — malformed construction and merges raise
  (:class:`CRDTError` / ``TypeError``); a merge never silently drops a
  replica's contribution.

Honest scope: merge is *convergent*, not *authenticated* — a Byzantine
replica can inflate its own entry and the max-merge will adopt it
(inflation is the :mod:`federated_attack_detector` layer's job, not this
module's). A merged value means "every replica's reported contributions,
max-per-replica", never "the true count". Cross-restart persistence is the
host's job; this module holds state in memory.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Mapping, Optional, Tuple

#: Module version.
CRDT_INTERFACE_VERSION = "crdt-interface.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.crdt-interface.v1"


class CRDTError(Exception):
    """Malformed input to a CRDT (programming error)."""


def _check_replica_id(replica_id: object) -> str:
    if isinstance(replica_id, bool) or not isinstance(replica_id, str):
        raise CRDTError(f"replica_id must be a non-empty str, got {replica_id!r}")
    if not replica_id:
        raise CRDTError("replica_id must be non-empty")
    return replica_id


def _check_delta(n: object, what: str) -> int:
    if isinstance(n, bool) or not isinstance(n, int):
        raise CRDTError(f"{what} must be a positive int, got {n!r}")
    if n <= 0:
        raise CRDTError(f"{what} must be positive, got {n}")
    return n


def _check_counts(counts: object) -> Tuple[Tuple[str, int], ...]:
    """Normalize a counts mapping to sorted tuple-of-tuples (hashable)."""
    if isinstance(counts, tuple):
        items = list(counts)
        for entry in items:
            if (
                not isinstance(entry, tuple)
                or len(entry) != 2
                or isinstance(entry[0], bool)
                or not isinstance(entry[1], int)
                or isinstance(entry[1], bool)
            ):
                raise CRDTError(f"malformed counts entry: {entry!r}")
            rid, val = entry
            if not isinstance(rid, str) or not rid:
                raise CRDTError(f"malformed replica id in counts: {rid!r}")
            if val < 0:
                raise CRDTError(f"counts must be non-negative, got {val} for {rid!r}")
        return tuple(sorted(items, key=lambda e: e[0]))
    if isinstance(counts, Mapping):
        items: list[Tuple[str, int]] = []
        for rid, val in counts.items():
            if isinstance(rid, bool) or not isinstance(rid, str) or not rid:
                raise CRDTError(f"malformed replica id in counts: {rid!r}")
            if isinstance(val, bool) or not isinstance(val, int) or val < 0:
                raise CRDTError(f"counts must be non-negative ints, got {val!r} for {rid!r}")
            items.append((rid, val))
        return tuple(sorted(items, key=lambda e: e[0]))
    raise CRDTError(f"counts must be a mapping or tuple of pairs, got {counts!r}")


def _as_map(counts: Tuple[Tuple[str, int], ...]) -> Dict[str, int]:
    return dict(counts)


@dataclass(frozen=True)
class GCounter:
    """Grow-only counter.

    ``counts`` maps each known replica id to that replica's reported total.
    Only the owning replica's entry may be advanced (via :meth:`increment`);
    :meth:`merge` takes the per-replica maximum, which is what makes the
    merge order-independent.
    """

    replica_id: str
    counts: Tuple[Tuple[str, int], ...] = ()

    def __post_init__(self) -> None:
        rid = _check_replica_id(self.replica_id)
        normalized = _check_counts(self.counts)
        # Detect duplicate replica ids in a tuple-form input.
        seen = set()
        for entry_rid, _ in normalized:
            if entry_rid in seen:
                raise CRDTError(f"duplicate replica id in counts: {entry_rid!r}")
            seen.add(entry_rid)
        # Normalize to sorted order (frozen dataclass: use object.__setattr__).
        object.__setattr__(self, "replica_id", rid)
        object.__setattr__(self, "counts", normalized)

    @property
    def value(self) -> int:
        """Total across all known replicas."""
        return sum(val for _, val in self.counts)

    def increment(self, n: int = 1) -> "GCounter":
        """Return a new counter with this replica's entry advanced by ``n``."""
        delta = _check_delta(n, "increment amount")
        known = _as_map(self.counts)
        known[self.replica_id] = known.get(self.replica_id, 0) + delta
        return GCounter(self.replica_id, known)

    def merge(self, other: "GCounter") -> "GCounter":
        """Return the least upper bound of both counters (per-replica max)."""
        if not isinstance(other, GCounter):
            raise TypeError(f"can only merge GCounter with GCounter, got {type(other).__name__}")
        merged = _as_map(self.counts)
        for rid, val in other.counts:
            if val > merged.get(rid, 0):
                merged[rid] = val
        return GCounter(self.replica_id, merged)

    def as_dict(self) -> dict:
        """JSON-safe record of this counter."""
        return {
            "schema": SCHEMA_PIN,
            "kind": "gcounter",
            "replica_id": self.replica_id,
            "counts": {rid: val for rid, val in self.counts},
            "value": self.value,
        }


@dataclass(frozen=True)
class PNCounter:
    """Positive-negative counter: ``value = inc.value - dec.value``.

    Both halves are grow-only, so the merge stays convergent while the
    counter supports decrement.
    """

    replica_id: str
    inc: GCounter = None  # type: ignore[assignment]
    dec: GCounter = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        rid = _check_replica_id(self.replica_id)
        inc = self.inc if self.inc is not None else GCounter(rid)
        dec = self.dec if self.dec is not None else GCounter(rid)
        if not isinstance(inc, GCounter) or not isinstance(dec, GCounter):
            raise CRDTError("inc and dec must be GCounter instances")
        object.__setattr__(self, "replica_id", rid)
        object.__setattr__(self, "inc", inc)
        object.__setattr__(self, "dec", dec)

    @property
    def value(self) -> int:
        """Net value: increments minus decrements."""
        return self.inc.value - self.dec.value

    def increment(self, n: int = 1) -> "PNCounter":
        """Return a new counter with this replica's increments advanced."""
        delta = _check_delta(n, "increment amount")
        return PNCounter(self.replica_id, self.inc.increment(delta), self.dec)

    def decrement(self, n: int = 1) -> "PNCounter":
        """Return a new counter with this replica's decrements advanced."""
        delta = _check_delta(n, "decrement amount")
        return PNCounter(self.replica_id, self.inc, self.dec.increment(delta))

    def merge(self, other: "PNCounter") -> "PNCounter":
        """Return the least upper bound of both counters (both halves merged)."""
        if not isinstance(other, PNCounter):
            raise TypeError(f"can only merge PNCounter with PNCounter, got {type(other).__name__}")
        return PNCounter(
            self.replica_id,
            self.inc.merge(other.inc),
            self.dec.merge(other.dec),
        )

    def as_dict(self) -> dict:
        """JSON-safe record of this counter."""
        return {
            "schema": SCHEMA_PIN,
            "kind": "pncounter",
            "replica_id": self.replica_id,
            "inc": {rid: val for rid, val in self.inc.counts},
            "dec": {rid: val for rid, val in self.dec.counts},
            "value": self.value,
        }


def crdt_audit_event(kind: str, counter: object, seq: int) -> dict:
    """Build an ``audit.ndjson/1``-shaped record for a CRDT operation.

    ``kind`` is a fixed vocabulary: ``increment`` / ``decrement`` /
    ``merge``. ``seq`` is the caller's sequence number (no wall-clock).
    """
    if kind not in ("increment", "decrement", "merge"):
        raise CRDTError(f"unknown audit kind: {kind!r}")
    if not isinstance(counter, (GCounter, PNCounter)):
        raise TypeError(f"counter must be GCounter or PNCounter, got {type(counter).__name__}")
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise CRDTError(f"seq must be a non-negative int, got {seq!r}")
    record = counter.as_dict()
    record.update(
        {
            "event": "crdt",
            "kind": kind,
            "audit_seq": seq,
        }
    )
    return record


def main() -> None:
    """Self-check: two replicas converge regardless of merge order."""
    a = GCounter("a").increment(3)
    b = GCounter("b").increment(5)
    assert a.merge(b).value == 8
    assert b.merge(a).value == 8  # commutativity
    assert a.merge(a).value == 3  # idempotence

    p1 = PNCounter("a").increment(10).decrement(4)
    p2 = PNCounter("b").increment(7).decrement(2)
    merged = p1.merge(p2)
    assert merged.value == (10 + 7) - (4 + 2), merged.value
    assert p2.merge(p1).value == merged.value  # commutativity

    ev = crdt_audit_event("merge", merged, seq=1)
    assert ev["schema"] == SCHEMA_PIN and ev["audit_seq"] == 1

    print("crdt-interface OK: grow-only and PN counters converge")


if __name__ == "__main__":
    main()
