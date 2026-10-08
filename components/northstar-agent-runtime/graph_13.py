"""graph_13: Prim's minimum spanning tree. Standard library only.

GRAPH_13_VERSION = graph-13.v1
"""
from __future__ import annotations

import heapq
from typing import Dict, Hashable, List, Tuple

GRAPH_13_VERSION = "graph-13.v1"


def prim(
    graph: Dict[Hashable, List[Tuple[Hashable, float]]], start: Hashable
) -> Tuple[List[Tuple[Hashable, Hashable, float]], float]:
    """Prim's MST from start; returns (mst_edges, total). Assumes connected."""
    visited = {start}
    mst: List[Tuple[Hashable, Hashable, float]] = []
    total = 0.0
    pq: List[Tuple[float, Hashable, Hashable]] = [
        (w, start, v) for v, w in graph.get(start, [])
    ]
    heapq.heapify(pq)
    while pq:
        w, u, v = heapq.heappop(pq)
        if v in visited:
            continue
        visited.add(v)
        mst.append((u, v, w))
        total += w
        for to, w2 in graph.get(v, []):
            if to not in visited:
                heapq.heappush(pq, (w2, v, to))
    return mst, total


def test_prim_basic():
    g = {"a": [("b", 1), ("c", 3)], "b": [("a", 1), ("c", 2)], "c": [("a", 3), ("b", 2)]}
    _, total = prim(g, "a")
    assert total == 3.0


def test_prim_classic():
    g = {
        "a": [("b", 4), ("h", 8)], "b": [("a", 4), ("c", 8), ("h", 11)],
        "c": [("b", 8), ("d", 7), ("f", 4), ("i", 2)],
        "d": [("c", 7), ("e", 9), ("f", 14)], "e": [("d", 9), ("f", 10)],
        "f": [("c", 4), ("d", 14), ("e", 10), ("g", 2)],
        "g": [("f", 2), ("h", 1), ("i", 6)], "h": [("a", 8), ("b", 11), ("g", 1), ("i", 7)],
        "i": [("c", 2), ("g", 6), ("h", 7)],
    }
    _, total = prim(g, "a")
    assert total == 37.0


def test_prim_agrees_with_kruskal_weight():
    import sys
    sys.path.insert(0, __file__.rsplit("/", 1)[0])
    import graph_12

    edges = [("a", "b", 4), ("a", "h", 8), ("b", "c", 8), ("f", "g", 2), ("g", "h", 1)]
    g: Dict[Hashable, List[Tuple[Hashable, float]]] = {}
    for u, v, w in edges:
        g.setdefault(u, []).append((v, w))
        g.setdefault(v, []).append((u, w))
    _, tp = prim(g, "a")
    _, tk = graph_12.kruskal(edges)
    assert tp == tk


def test_prim_single_node():
    assert prim({"a": []}, "a") == ([], 0.0)


def main() -> None:
    test_prim_basic()
    test_prim_classic()
    test_prim_agrees_with_kruskal_weight()
    test_prim_single_node()
    print("graph_13 (Prim) OK")


if __name__ == "__main__":
    main()
