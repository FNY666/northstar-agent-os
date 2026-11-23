"""State 11: G-counter CRDT, Simulated.

Grow-only counter CRDT: each replica holds a vector of per-node counts.
- increment(node): local count += 1
- merge(other): element-wise max
- value(): sum of all entries

Merge is commutative, associative, idempotent — replicas converge
without coordination.

Fail-closed: unknown node on increment, mismatched node sets on merge
raise (explicit join required).
"""

from __future__ import annotations

import ast
from typing import Dict, Set

MODULE_VERSION = "state-mgmt-11.v1"
SCHEMA_PIN = "northstar.state-mgmt-11.v1"


class CRDTError(Exception):
    pass


class GCounter:
    def __init__(self, node_id: str, nodes: Set[str] | None = None) -> None:
        if not node_id:
            raise CRDTError("node_id required")
        self.node_id = node_id
        self.counts: Dict[str, int] = {}
        if nodes:
            for n in nodes:
                self.counts[n] = 0
        self.counts.setdefault(node_id, 0)

    def join(self, node: str) -> None:
        if not node:
            raise CRDTError("node required")
        self.counts.setdefault(node, 0)

    def increment(self, n: int = 1) -> None:
        if n < 1:
            raise CRDTError("n must be >= 1")
        self.counts[self.node_id] += n

    def merge(self, other: "GCounter") -> None:
        if set(self.counts) != set(other.counts):
            raise CRDTError("node sets differ; join missing nodes first")
        for node in self.counts:
            self.counts[node] = max(self.counts[node], other.counts[node])

    def value(self) -> int:
        return sum(self.counts.values())

    def snapshot(self) -> Dict[str, int]:
        return dict(self.counts)


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
    a = GCounter("a", {"a", "b"})
    b = GCounter("b", {"a", "b"})
    a.increment(3)
    b.increment(2)
    # Merge both ways: converge.
    a.merge(b)
    b.merge(a)
    assert a.value() == 5 and b.value() == 5
    assert a.snapshot() == b.snapshot()
    # Idempotent.
    a.merge(b)
    assert a.value() == 5
    # Mismatched node sets -> fail-closed.
    c = GCounter("c")
    try:
        a.merge(c)
        raise AssertionError("should raise")
    except CRDTError:
        pass
    # After join, merge works.
    a.join("c")
    c.join("a"); c.join("b")
    a.merge(c)
    assert a.value() == 5
    assert stdlib_only()
    print("state_mgmt_11 OK: G-counter, merge convergence, fail-closed")


if __name__ == "__main__":
    main()
