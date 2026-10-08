"""State 29: CRDT counters (G-counter + PN-counter).

G-counter (grow-only): per-node counts, merge = element-wise max,
value = sum.  Only increment.

PN-counter: two G-counters (increments, decrements); value = inc - dec.
Supports decrement while staying mergeable.

Both are commutative/associative/idempotent — replicas converge.

Fail-closed: increment on unknown node, decrement below... (PN allows
any decrement; negative values are legal), mismatched node sets on
merge raise (explicit join required).
"""

from __future__ import annotations

import ast
from typing import Dict, Set


MODULE_VERSION = "state-mgmt-29.v1"
SCHEMA_PIN = "northstar.state-mgmt-29.v1"


class CounterError(Exception):
    pass


class GCounter:
    def __init__(self, node_id: str, peers: Set[str]) -> None:
        if not node_id:
            raise CounterError("node_id required")
        if node_id not in peers:
            raise CounterError("node_id must be in peers")
        self.node_id = node_id
        self.peers = set(peers)
        self.counts: Dict[str, int] = {p: 0 for p in peers}

    def increment(self, amount: int = 1) -> None:
        if not isinstance(amount, int) or isinstance(amount, bool) or amount <= 0:
            raise CounterError("amount must be positive int")
        self.counts[self.node_id] += amount

    def value(self) -> int:
        return sum(self.counts.values())

    def merge(self, other: "GCounter") -> None:
        if not isinstance(other, GCounter):
            raise CounterError("merge requires a GCounter")
        if other.peers != self.peers:
            raise CounterError("peer set mismatch")
        for p in self.peers:
            self.counts[p] = max(self.counts[p], other.counts[p])


class PNCounter:
    def __init__(self, node_id: str, peers: Set[str]) -> None:
        self._inc = GCounter(node_id, peers)
        self._dec = GCounter(node_id, peers)
        self.node_id = node_id
        self.peers = set(peers)

    def increment(self, amount: int = 1) -> None:
        self._inc.increment(amount)

    def decrement(self, amount: int = 1) -> None:
        if not isinstance(amount, int) or isinstance(amount, bool) or amount <= 0:
            raise CounterError("amount must be positive int")
        self._dec.counts[self.node_id] += amount

    def value(self) -> int:
        return self._inc.value() - self._dec.value()

    def merge(self, other: "PNCounter") -> None:
        if not isinstance(other, PNCounter):
            raise CounterError("merge requires a PNCounter")
        self._inc.merge(other._inc)
        self._dec.merge(other._dec)


def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib", "typing"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for x in node.names:
                if x.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    peers = {"a", "b"}
    ga, gb = GCounter("a", peers), GCounter("b", peers)
    ga.increment(2); gb.increment(3)
    ga.merge(gb); gb.merge(ga)
    assert ga.value() == gb.value() == 5
    # Idempotent merge.
    ga.merge(gb)
    assert ga.value() == 5
    pa, pb = PNCounter("a", peers), PNCounter("b", peers)
    pa.increment(10); pa.decrement(4)
    pb.increment(5); pb.decrement(7)
    pa.merge(pb); pb.merge(pa)
    assert pa.value() == pb.value() == (15 - 11) == 4
    # Peer mismatch -> fail-closed.
    try:
        ga.merge(GCounter("a", {"a"}))
        raise AssertionError("should raise")
    except CounterError:
        pass
    assert stdlib_only()
    print("state_mgmt_29 OK: G-counter + PN-counter, merge, fail-closed")


if __name__ == "__main__":
    main()
