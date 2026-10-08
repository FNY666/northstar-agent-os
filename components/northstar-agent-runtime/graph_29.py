"""graph_29: Lowest common ancestor with binary lifting. Standard library only.

GRAPH_29_VERSION = graph-29.v1
"""
from __future__ import annotations

import math
from collections import deque
from typing import Dict, Hashable, List

GRAPH_29_VERSION = "graph-29.v1"


class LCA:
    """Binary lifting LCA on a rooted tree (undirected adjacency + root)."""

    def __init__(self, graph: Dict[Hashable, List[Hashable]], root: Hashable) -> None:
        nodes = list(graph)
        self.n = len(nodes)
        self.LOG = max(1, math.ceil(math.log2(self.n + 1)))
        self.up: Dict[Hashable, List[Hashable | None]] = {u: [None] * self.LOG for u in nodes}
        self.depth: Dict[Hashable, int] = {}
        # BFS to set parents/depths
        self.depth[root] = 0
        q: deque = deque([root])
        seen = {root}
        order = [root]
        while q:
            u = q.popleft()
            for v in graph.get(u, []):
                if v not in seen:
                    seen.add(v)
                    self.depth[v] = self.depth[u] + 1
                    self.up[v][0] = u
                    q.append(v)
                    order.append(v)
        self.up[root][0] = None
        for k in range(1, self.LOG):
            for u in order:
                mid = self.up[u][k - 1]
                self.up[u][k] = self.up[mid][k - 1] if mid is not None else None

    def lca(self, a: Hashable, b: Hashable) -> Hashable:
        if self.depth[a] < self.depth[b]:
            a, b = b, a
        # lift a to depth of b
        diff = self.depth[a] - self.depth[b]
        k = 0
        while diff:
            if diff & 1:
                nxt = self.up[a][k]
                assert nxt is not None
                a = nxt
            diff >>= 1
            k += 1
        if a == b:
            return a
        for k in range(self.LOG - 1, -1, -1):
            ua, ub = self.up[a][k], self.up[b][k]
            if ua is not None and ub is not None and ua != ub:
                a, b = ua, ub
        parent = self.up[a][0]
        assert parent is not None
        return parent

    def distance(self, a: Hashable, b: Hashable) -> int:
        w = self.lca(a, b)
        return self.depth[a] + self.depth[b] - 2 * self.depth[w]


def test_lca_basic():
    g = {1: [2, 3], 2: [1, 4, 5], 3: [1], 4: [2], 5: [2]}
    l = LCA(g, 1)
    assert l.lca(4, 5) == 2
    assert l.lca(4, 3) == 1
    assert l.lca(2, 5) == 2


def test_lca_self():
    g = {1: [2], 2: [1]}
    l = LCA(g, 1)
    assert l.lca(2, 2) == 2


def test_lca_distance():
    g = {1: [2, 3], 2: [1, 4, 5], 3: [1], 4: [2], 5: [2]}
    l = LCA(g, 1)
    assert l.distance(4, 5) == 2
    assert l.distance(4, 3) == 3


def test_lca_chain():
    g = {1: [2], 2: [1, 3], 3: [2, 4], 4: [3]}
    l = LCA(g, 1)
    assert l.lca(3, 4) == 3
    assert l.lca(1, 4) == 1


def test_lca_root():
    g = {1: [2, 3], 2: [1], 3: [1]}
    l = LCA(g, 1)
    assert l.lca(2, 3) == 1


def main() -> None:
    test_lca_basic()
    test_lca_self()
    test_lca_distance()
    test_lca_chain()
    test_lca_root()
    print("graph_29 (LCA) OK")


if __name__ == "__main__":
    main()
