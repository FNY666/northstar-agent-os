"""graph_14: Boruvka's minimum spanning tree. Standard library only.

GRAPH_14_VERSION = graph-14.v1
"""
from __future__ import annotations

from typing import Dict, Hashable, List, Tuple

GRAPH_14_VERSION = "graph-14.v1"


def boruvka(
    nodes: List[Hashable], edges: List[Tuple[Hashable, Hashable, float]]
) -> Tuple[List[Tuple[Hashable, Hashable, float]], float]:
    """Boruvka's MST via repeated cheapest-outgoing-edge contraction."""
    parent = {n: n for n in nodes}

    def find(x: Hashable) -> Hashable:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    mst: List[Tuple[Hashable, Hashable, float]] = []
    total = 0.0
    num_components = len(nodes)
    while num_components > 1:
        cheapest: Dict[Hashable, Tuple[Hashable, Hashable, float]] = {}
        for u, v, w in edges:
            ru, rv = find(u), find(v)
            if ru == rv:
                continue
            if ru not in cheapest or w < cheapest[ru][2]:
                cheapest[ru] = (u, v, w)
            if rv not in cheapest or w < cheapest[rv][2]:
                cheapest[rv] = (u, v, w)
        if not cheapest:
            break  # disconnected remainder
        merged = 0
        for u, v, w in cheapest.values():
            ru, rv = find(u), find(v)
            if ru != rv:
                parent[rv] = ru
                mst.append((u, v, w))
                total += w
                merged += 1
        if merged == 0:
            break
        num_components -= merged
    return mst, total


def test_boruvka_basic():
    nodes = ["a", "b", "c"]
    edges = [("a", "b", 1), ("b", "c", 2), ("a", "c", 3)]
    _, total = boruvka(nodes, edges)
    assert total == 3.0


def test_boruvka_matches_known_weight():
    # hand-computed MST weight 3.0
    nodes = ["a", "b", "c"]
    edges = [("a", "b", 1), ("b", "c", 2), ("a", "c", 3)]
    _, total = boruvka(nodes, edges)
    assert total == 3.0


def test_boruvka_disconnected():
    nodes = ["a", "b", "c", "d"]
    edges = [("a", "b", 1), ("c", "d", 2)]
    mst, total = boruvka(nodes, edges)
    assert total == 3.0 and len(mst) == 2


def test_boruvka_single():
    assert boruvka(["a"], []) == ([], 0.0)


def main() -> None:
    test_boruvka_basic()
    test_boruvka_matches_known_weight()
    test_boruvka_disconnected()
    test_boruvka_single()
    print("graph_14 (Boruvka) OK")


if __name__ == "__main__":
    main()
