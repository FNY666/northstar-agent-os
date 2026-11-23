"""State 25: multi-value register.

Keeps every concurrent write instead of picking a winner.  Each write
carries a dot (node, counter); a write A dominates B if A's version
vector >= B's.  get() returns all non-dominated values.

Useful when conflicts must be surfaced to the application instead of
being resolved automatically.

Fail-closed: malformed dots, unknown nodes, or non-monotonic local
counters raise.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Any, Dict, List, Set


MODULE_VERSION = "state-mgmt-25.v1"
SCHEMA_PIN = "northstar.state-mgmt-25.v1"


class MVError(Exception):
    pass


@dataclass(frozen=True)
class Dot:
    node: str
    counter: int

    def __post_init__(self):
        if not self.node:
            raise MVError("dot node required")
        if not isinstance(self.counter, int) or isinstance(self.counter, bool) \
                or self.counter <= 0:
            raise MVError("dot counter must be positive int")


@dataclass(frozen=True)
class VersionedValue:
    value: Any
    dot: Dot
    # version vector at write time: node -> max counter seen
    vv: Dict[str, int]

    def __post_init__(self):
        for k, v in self.vv.items():
            if not k or not isinstance(v, int) or isinstance(v, bool) or v < 0:
                raise MVError("malformed version vector")


def dominates(a: VersionedValue, b: VersionedValue) -> bool:
    """True if a causally dominates b (a.vv >= b.dot and not equal dots)."""
    if a.dot == b.dot:
        return False
    return a.vv.get(b.dot.node, 0) >= b.dot.counter


class MVRegister:
    def __init__(self, node_id: str, peers: Set[str]) -> None:
        if not node_id:
            raise MVError("node_id required")
        if node_id not in peers:
            raise MVError("node_id must be in peers")
        self.node_id = node_id
        self.peers = set(peers)
        self._counter = 0
        self._vv: Dict[str, int] = {p: 0 for p in peers}
        self._values: List[VersionedValue] = []

    def set(self, value: Any) -> Dot:
        self._counter += 1
        dot = Dot(self.node_id, self._counter)
        vv = dict(self._vv)
        vv[self.node_id] = self._counter
        self._vv = vv
        self._values.append(VersionedValue(value, dot, dict(vv)))
        self._prune()
        return dot

    def _prune(self) -> None:
        live = []
        for v in self._values:
            if not any(dominates(o, v) for o in self._values if o is not v):
                live.append(v)
        self._values = live

    def get(self) -> List[Any]:
        return [v.value for v in self._values]

    def merge(self, other: "MVRegister") -> None:
        if not isinstance(other, MVRegister):
            raise MVError("merge requires an MVRegister")
        if other.peers != self.peers:
            raise MVError("peer set mismatch")
        for v in other._values:
            if v.dot.node not in self.peers:
                raise MVError(f"unknown dot node {v.dot.node!r}")
            if all(existing.dot != v.dot for existing in self._values):
                self._values.append(v)
        for node, cnt in other._vv.items():
            self._vv[node] = max(self._vv.get(node, 0), cnt)
        self._prune()


def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "dataclasses", "pathlib", "typing"}
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
    ra, rb = MVRegister("a", peers), MVRegister("b", peers)
    ra.set("A")
    rb.set("B")  # concurrent: neither dominates
    ra.merge(rb); rb.merge(ra)
    assert sorted(ra.get()) == ["A", "B"]
    assert sorted(rb.get()) == ["A", "B"]
    # A later write dominates the earlier one from the same node.
    ra.set("A2")
    assert "A" not in ra.get() and "A2" in ra.get()
    # Malformed dot -> fail-closed.
    try:
        Dot("", 1)
        raise AssertionError("should raise")
    except MVError:
        pass
    assert stdlib_only()
    print("state_mgmt_25 OK: concurrent values kept, dominance prune")


if __name__ == "__main__":
    main()
