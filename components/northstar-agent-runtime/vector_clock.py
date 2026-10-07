"""Vector clock: causality tracking across nodes.

Research motivation: a fleet of cooperating agents (or one agent's
subagents) produces events on different hosts with no shared wall clock.
Vector clocks (Lamport 1978; Fidge 1988; Mattern 1989) recover *causal
order* from the message-passing structure alone: clock ``a`` precedes
clock ``b`` when every counter in ``a`` is ``<=`` the corresponding
counter in ``b`` and at least one is strictly smaller.

Public API:

- ``VectorClock`` -- frozen immutable record: a mapping of
  ``node_id -> int`` counters (missing entry means 0). ``tick(node_id)``
  returns a *new* clock with the node's counter incremented;
  ``merge(other)`` returns a new clock with the elementwise maximum;
  ``happens_before(other)`` answers the causal-order question;
  ``concurrent_with(other)`` is the negation of both orderings;
  ``compare(other)`` returns one of ``"before"``, ``"after"``,
  ``"equal"``, ``"concurrent"``.
- ``vector_clock_audit_event(clock, kind, seq)`` -- ``audit.ndjson/1``-shaped
  record, fixed kind vocabulary: ``"tick"``, ``"merge"``, ``"compare"``.

Honest scope:

- This module *compares* clocks and *constructs* them from host-reported
  events; it cannot observe messages the host never reports. A clock is
  only as truthful as the event stream it was built from.
- A new node id seen by ``tick`` starts at 1 (the standard convention);
  this module cannot distinguish a genuinely new participant from a
  misspelled id -- the host owns the id registry.
- ``happens_before`` treats a node absent from one clock as counter 0 in
  that clock. Two clocks that share no causal chain compare as
  ``"concurrent"`` -- concurrency is a verdict about *this evidence*,
  never a claim that the events were truly unordered in the world.
- Clocks are immutable snapshots; the host keeps whatever mutable
  per-node state it needs. This module never invents seq numbers and
  never reaches the network.

Version pin: ``vector-clock.v1`` / schema pin ``northstar.vector-clock.v1``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Mapping

#: Module version.
VECTOR_CLOCK_VERSION = "vector-clock.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.vector-clock.v1"

#: Version pin carried inside audit records.
AUDIT_FORMAT = "audit.ndjson/1"

#: Fixed vocabulary for ``compare`` results.
BEFORE = "before"
AFTER = "after"
EQUAL = "equal"
CONCURRENT = "concurrent"

#: Fixed vocabulary for audit event kinds.
_AUDIT_KINDS = frozenset({"tick", "merge", "compare"})

_MAX_COUNTER = 2**63 - 1


def _check_node_id(node_id: object) -> str:
    """Validate a node id. Returns it, or raises fail-closed."""
    if isinstance(node_id, bool) or not isinstance(node_id, str):
        raise TypeError(f"node_id must be str, got {type(node_id).__name__}")
    if not node_id:
        raise ValueError("node_id must be non-empty")
    if len(node_id) > 1024:
        raise ValueError("node_id exceeds 1024 chars")
    return node_id


def _check_counter(node_id: str, value: object) -> int:
    """Validate one counter. Returns it as int, or raises fail-closed."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(
            f"counter for {node_id!r} must be int, got {type(value).__name__}"
        )
    if value < 0:
        raise ValueError(f"counter for {node_id!r} must be non-negative")
    if value > _MAX_COUNTER:
        raise ValueError(f"counter for {node_id!r} exceeds {_MAX_COUNTER}")
    return value


@dataclass(frozen=True)
class VectorClock:
    """Immutable causality snapshot: node_id -> counter.

    Constructed directly (``VectorClock(counters={"a": 1})``) for
    host-reported state, or grown with ``tick``/``merge``. A node absent
    from ``counters`` is read as 0 everywhere comparisons are concerned.
    """

    counters: Mapping[str, int]

    def __post_init__(self) -> None:
        if not isinstance(self.counters, Mapping):
            raise TypeError(
                f"counters must be a Mapping, got {type(self.counters).__name__}"
            )
        clean: Dict[str, int] = {}
        for node_id, value in self.counters.items():
            clean[_check_node_id(node_id)] = _check_counter(node_id, value)
        object.__setattr__(self, "counters", clean)

    def get(self, node_id: str) -> int:
        """Counter for ``node_id``; 0 when the node is unknown to this clock."""
        _check_node_id(node_id)
        return self.counters.get(node_id, 0)

    def tick(self, node_id: str) -> "VectorClock":
        """Return a new clock with ``node_id``'s counter incremented by one.

        A node never seen before starts at 1 (standard vector-clock
        convention). Never raises on policy; validates the id.
        """
        _check_node_id(node_id)
        new_counters = dict(self.counters)
        new_counters[node_id] = self.get(node_id) + 1
        return VectorClock(counters=new_counters)

    def merge(self, other: "VectorClock") -> "VectorClock":
        """Return a new clock holding the elementwise maximum of both.

        The host calls this when an event at ``other`` causally depends on
        (e.g. is received after) an event at this clock. Never raises on
        policy; ``TypeError`` on non-clock input.
        """
        if not isinstance(other, VectorClock):
            raise TypeError(
                f"merge expects VectorClock, got {type(other).__name__}"
            )
        nodes = set(self.counters) | set(other.counters)
        return VectorClock(
            counters={
                node: max(self.get(node), other.get(node)) for node in nodes
            }
        )

    def happens_before(self, other: "VectorClock") -> bool:
        """True iff this clock causally precedes ``other``.

        Per the Fidge/Mattern rule: every counter here is ``<=`` the
        corresponding counter in ``other`` (absent = 0) and at least one
        counter is strictly smaller. Never raises on policy.
        """
        if not isinstance(other, VectorClock):
            raise TypeError(
                f"happens_before expects VectorClock, got {type(other).__name__}"
            )
        nodes = set(self.counters) | set(other.counters)
        less = False
        for node in nodes:
            mine = self.get(node)
            theirs = other.get(node)
            if mine > theirs:
                return False
            if mine < theirs:
                less = True
        return less

    def concurrent_with(self, other: "VectorClock") -> bool:
        """True iff the clocks are causally incomparable and distinct.

        Defined via ``compare`` so an identical clock is not "concurrent
        with itself": only the ``"concurrent"`` verdict qualifies.
        """
        if not isinstance(other, VectorClock):
            raise TypeError(
                f"concurrent_with expects VectorClock, got {type(other).__name__}"
            )
        return self.compare(other) == CONCURRENT

    def compare(self, other: "VectorClock") -> str:
        """One of ``"before"`` / ``"after"`` / ``"equal"`` / ``"concurrent"``."""
        if not isinstance(other, VectorClock):
            raise TypeError(
                f"compare expects VectorClock, got {type(other).__name__}"
            )
        if self.counters == other.counters:
            return EQUAL
        if self.happens_before(other):
            return BEFORE
        if other.happens_before(self):
            return AFTER
        return CONCURRENT

    def as_dict(self) -> dict:
        """JSON-safe record with the schema pin."""
        return {
            "schema": SCHEMA_PIN,
            "counters": dict(sorted(self.counters.items())),
        }


def _check_seq(seq: object) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise TypeError(f"seq must be int, got {type(seq).__name__}")
    if seq < 0:
        raise ValueError("seq must be non-negative")
    return seq


def vector_clock_audit_event(clock: VectorClock, kind: str, seq: int) -> dict:
    """Build an ``audit.ndjson/1``-shaped record for a clock operation.

    ``kind`` is one of ``"tick"`` / ``"merge"`` / ``"compare"``.
    """
    if not isinstance(clock, VectorClock):
        raise TypeError(
            f"clock must be VectorClock, got {type(clock).__name__}"
        )
    if not isinstance(kind, str) or kind not in _AUDIT_KINDS:
        raise ValueError(f"kind must be one of {sorted(_AUDIT_KINDS)}")
    return {
        "format": AUDIT_FORMAT,
        "schema": SCHEMA_PIN,
        "kind": kind,
        "clock": clock.as_dict(),
        "seq": _check_seq(seq),
    }


def main() -> None:
    """Self-check: tick, merge, and all four compare outcomes."""
    a = VectorClock(counters={})
    b = a.tick("node-a")          # {'node-a': 1}
    c = b.tick("node-a")          # {'node-a': 2}
    assert b.happens_before(c), "tick must strictly advance"
    assert c.compare(b) == AFTER

    d = a.tick("node-b")          # {'node-b': 1}
    assert b.concurrent_with(d), "independent ticks are concurrent"
    assert b.compare(d) == CONCURRENT

    merged = b.merge(d)          # {'node-a': 1, 'node-b': 1}
    assert merged.counters == {"node-a": 1, "node-b": 1}
    assert b.happens_before(merged)
    assert merged.compare(b) == AFTER

    assert VectorClock(counters={"x": 1}).compare(
        VectorClock(counters={"x": 1})
    ) == EQUAL

    # A clock with a foreign node can never precede one without it.
    # The empty clock is the bottom element: every non-empty clock
    # happens *after* it, so they are not concurrent either.
    e = VectorClock(counters={"y": 1})
    assert not e.happens_before(VectorClock(counters={}))
    assert e.compare(VectorClock(counters={})) == AFTER
    assert not e.concurrent_with(VectorClock(counters={}))

    print("vector-clock OK: tick, merge, before/after/equal/concurrent")
    print("audit:", vector_clock_audit_event(merged, "merge", 1)["kind"])


if __name__ == "__main__":
    main()
