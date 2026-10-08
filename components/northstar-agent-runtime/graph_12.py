"""graph_12: Kruskal's minimum spanning tree. Standard library only.

GRAPH_12_VERSION = graph-12.v1
"""
from __future__ import annotations

from typing import Hashable, List, Tuple

GRAPH_12_VERSION = "graph-12.v1"


class _DSU:
    def __init__(self) -> None:
        self.p: dict = {}

    def find(self, x: Hashable) -> Hashable:
        self.p.setdefault(x, x)
        while self.p[x] != x:
            self.p[x] = self.p[self.p[x]]
            x = self.p[x]
        return x

    def union(self, a: Hashable, b: Hashable) -> bool:
        ra, rb = self.find(a), self.find(b)
        if ra == rb:
            return False
        self.p[rb] = ra
        return True


def kruskal(
    edges: List[Tuple[Hashable, Hashable, float]],
) -> Tuple[List[Tuple[Hashable, Hashable, float]], float]:
    """Returns (mst_edges, total_weight). Works on disconnected graphs (forest)."""
    dsu = _DSU()
    mst: List[Tuple[Hashable, Hashable, float]] = []
    total = 0.0
    for u, v, w in sorted(edges, key=lambda e: e[2]):
        if dsu.union(u, v):
            mst.append((u, v, w))
            total += w
    return mst, total


def test_kruskal_basic():
    edges = [("a", "b", 1), ("b", "c", 2), ("a", "c", 3)]
    mst, total = kruskal(edges)
    assert total == 3.0
    assert len(mst) == 2


def test_kruskal_classic():
    edges = [
        ("a", "b", 4), ("a", "h", 8), ("b", "c", 8), ("b", "h", 11),
        ("c", "d", 7), ("c", "f", 4), ("c", "i", 2), ("d", "e", 9),
        ("d", "f", 14), ("e", "f", 10), ("f", "g", 2), ("g", "h", 1),
        ("g", "i", 6), ("h", "i", 7),
    ]
    _, total = kruskal(edges)
    assert total == 37.0  # CLRS example


def test_kruskal_disconnected():
    edges = [("a", "b", 1), ("c", "d", 2)]
    mst, total = kruskal(edges)
    assert total == 3.0 and len(mst) == 2


def test_kruskal_empty():
    assert kruskal([]) == ([], 0.0)


def test_kruskal_tie_weights():
    edges = [("a", "b", 1), ("b", "c", 1), ("a", "c", 1)]
    mst, total = kruskal(edges)
    assert total == 2.0 and len(mst) == 2


def main() -> None:
    test_kruskal_basic()
    test_kruskal_classic()
    test_kruskal_disconnected()
    test_kruskal_empty()
    test_kruskal_tie_weights()
    print("graph_12 (Kruskal) OK")


if __name__ == "__main__":
    main()
