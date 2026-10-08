"""State 30: CRDT graphs (mock), Simulated.

Grow-only graph CRDT with OR-set semantics for vertices and edges:
- add_vertex(v) / add_edge(u, v): tagged adds (add-wins)
- remove_vertex(v): tombstones the vertex AND its incident edges
  (edges referencing a removed vertex are not returned)
- remove_edge(u, v): tombstones the edge tags
- merge(other): union of vertex/edge adds and tombstones

Mock: in-process; models the CRDT semantics including the classic
"edge whose endpoint was removed" rule.  Not a full production graph
store (no indexes, no queries beyond adjacency).

Fail-closed: empty vertex names, self-loops rejected, adding an edge
whose endpoints were never added raises.
"""

from __future__ import annotations

import ast
from typing import Dict, FrozenSet, Set, Tuple


MODULE_VERSION = "state-mgmt-30.v1"
SCHEMA_PIN = "northstar.state-mgmt-30.v1"


class GraphError(Exception):
    pass


Tag = Tuple[str, int]
Edge = FrozenSet[str]


class CRDTGraph:
    def __init__(self, node_id: str) -> None:
        if not node_id:
            raise GraphError("node_id required")
        self.node_id = node_id
        self._counter = 0
        self._v_adds: Dict[Tag, str] = {}
        self._v_tombs: Set[Tag] = set()
        self._e_adds: Dict[Tag, Edge] = {}
        self._e_tombs: Set[Tag] = set()

    def _tag(self) -> Tag:
        self._counter += 1
        return (self.node_id, self._counter)

    @staticmethod
    def _check_vertex(v: str) -> None:
        if not isinstance(v, str) or not v:
            raise GraphError("vertex must be non-empty str")

    def add_vertex(self, v: str) -> Tag:
        self._check_vertex(v)
        t = self._tag()
        self._v_adds[t] = v
        return t

    def remove_vertex(self, v: str) -> None:
        self._check_vertex(v)
        for t, name in self._v_adds.items():
            if name == v:
                self._v_tombs.add(t)
        for t, edge in self._e_adds.items():
            if v in edge:
                self._e_tombs.add(t)

    def add_edge(self, u: str, w: str) -> Tag:
        self._check_vertex(u)
        self._check_vertex(w)
        if u == w:
            raise GraphError("self-loops not allowed")
        live = self.vertices()
        if u not in live or w not in live:
            raise GraphError("edge endpoints must be live vertices")
        t = self._tag()
        self._e_adds[t] = frozenset((u, w))
        return t

    def remove_edge(self, u: str, w: str) -> None:
        edge = frozenset((u, w))
        for t, e in self._e_adds.items():
            if e == edge:
                self._e_tombs.add(t)

    def vertices(self) -> Set[str]:
        return {v for t, v in self._v_adds.items() if t not in self._v_tombs}

    def edges(self) -> Set[Tuple[str, str]]:
        live_v = self.vertices()
        out = set()
        for t, e in self._e_adds.items():
            if t in self._e_tombs:
                continue
            u, w = tuple(e)
            if u in live_v and w in live_v:
                out.add((u, w) if u < w else (w, u))
        return out

    def merge(self, other: "CRDTGraph") -> None:
        if not isinstance(other, CRDTGraph):
            raise GraphError("merge requires a CRDTGraph")
        self._v_adds.update(other._v_adds)
        self._v_tombs |= other._v_tombs
        self._e_adds.update(other._e_adds)
        self._e_tombs |= other._e_tombs
        for t in list(other._v_adds) + list(other._e_adds):
            if t[0] == self.node_id and t[1] > self._counter:
                self._counter = t[1]


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
    g, h = CRDTGraph("n1"), CRDTGraph("n2")
    g.add_vertex("a"); g.add_vertex("b"); g.add_edge("a", "b")
    h.add_vertex("c")
    g.merge(h); h.merge(g)
    assert g.vertices() == h.vertices() == {"a", "b", "c"}
    assert g.edges() == {("a", "b")}
    # Removing a vertex drops incident edges.
    g.remove_vertex("a")
    g.merge(h); h.merge(g)
    assert "a" not in h.vertices()
    assert h.edges() == set()
    # Edge with unknown endpoint -> fail-closed.
    try:
        h.add_edge("a", "c")
        raise AssertionError("should raise")
    except GraphError:
        pass
    # Self-loop -> fail-closed.
    try:
        h.add_edge("c", "c")
        raise AssertionError("should raise")
    except GraphError:
        pass
    assert stdlib_only()
    print("state_mgmt_30 OK: CRDT graph, vertex removal cascades, fail-closed")


if __name__ == "__main__":
    main()
