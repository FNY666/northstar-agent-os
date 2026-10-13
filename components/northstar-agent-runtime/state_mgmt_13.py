"""State 13: vector clocks, Simulated.

Vector clock per replica: {node: counter}.
- tick(node): increment own entry
- merge(other): element-wise max
- compare(a, b): "before" | "after" | "concurrent" | "equal"

Causality: a -> b iff a <= b element-wise and a != b.

Fail-closed: unknown nodes on tick, incomparable inputs raise only
where the API demands it (compare never raises; it returns
"concurrent").
"""

from __future__ import annotations

import ast
from typing import Dict, Set

MODULE_VERSION = "state-mgmt-13.v1"
SCHEMA_PIN = "northstar.state-mgmt-13.v1"


class VectorClockError(Exception):
    pass


class VectorClock:
    def __init__(self, node_id: str, nodes: Set[str] | None = None) -> None:
        if not node_id:
            raise VectorClockError("node_id required")
        self.node_id = node_id
        self.clock: Dict[str, int] = {}
        for n in nodes or set():
            self.clock[n] = 0
        self.clock.setdefault(node_id, 0)

    def join(self, node: str) -> None:
        if not node:
            raise VectorClockError("node required")
        self.clock.setdefault(node, 0)

    def tick(self) -> Dict[str, int]:
        self.clock[self.node_id] += 1
        return dict(self.clock)

    def update(self, other: Dict[str, int]) -> Dict[str, int]:
        """Receive: merge then tick own."""
        if set(other) - set(self.clock):
            raise VectorClockError("unknown nodes in received clock")
        for n, v in other.items():
            self.clock[n] = max(self.clock[n], v)
        return self.tick()

    @staticmethod
    def compare(a: Dict[str, int], b: Dict[str, int]) -> str:
        """before | after | concurrent | equal. Never raises."""
        keys = set(a) | set(b)
        le = all(a.get(k, 0) <= b.get(k, 0) for k in keys)
        ge = all(a.get(k, 0) >= b.get(k, 0) for k in keys)
        if le and ge:
            return "equal"
        if le:
            return "before"
        if ge:
            return "after"
        return "concurrent"


def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib", "typing"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    a = VectorClock("a", {"a", "b"})
    b = VectorClock("b", {"a", "b"})
    ca1 = a.tick()          # a:{a:1}
    cb1 = b.update(ca1)     # b merges, ticks -> {a:1,b:1}
    ca2 = a.update(cb1)     # a -> {a:2,b:1}
    assert VectorClock.compare(ca1, ca2) == "before"
    assert VectorClock.compare(ca2, ca1) == "after"
    assert VectorClock.compare(ca2, dict(ca2)) == "equal"
    # Concurrent: independent ticks.
    x = VectorClock("x", {"x", "y"})
    y = VectorClock("y", {"x", "y"})
    cx, cy = x.tick(), y.tick()
    assert VectorClock.compare(cx, cy) == "concurrent"
    # Unknown nodes -> fail-closed.
    try:
        a.update({"zzz": 9})
        raise AssertionError("should raise")
    except VectorClockError:
        pass
    assert stdlib_only()
    print("state_mgmt_13 OK: tick/merge/compare, fail-closed")


if __name__ == "__main__":
    main()
