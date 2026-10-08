"""graph_03: Dijkstra's shortest path (non-negative weights). Standard library only.

GRAPH_03_VERSION = graph-03.v1
"""
from __future__ import annotations

import heapq
from typing import Dict, Hashable, List, Optional, Tuple

GRAPH_03_VERSION = "graph-03.v1"


class NegativeWeightError(ValueError):
    """Raised when a negative edge weight is seen."""


def dijkstra(
    graph: Dict[Hashable, List[Tuple[Hashable, float]]], start: Hashable
) -> Tuple[Dict[Hashable, float], Dict[Hashable, Optional[Hashable]]]:
    """Returns (distances, predecessors). Raises NegativeWeightError."""
    dist: Dict[Hashable, float] = {start: 0.0}
    prev: Dict[Hashable, Optional[Hashable]] = {start: None}
    pq: List[Tuple[float, Hashable]] = [(0.0, start)]
    done = set()
    while pq:
        d, u = heapq.heappop(pq)
        if u in done:
            continue
        done.add(u)
        for v, w in graph.get(u, []):
            if w < 0:
                raise NegativeWeightError(f"negative weight on edge {u}->{v}")
            nd = d + w
            if nd < dist.get(v, float("inf")):
                dist[v] = nd
                prev[v] = u
                heapq.heappush(pq, (nd, v))
    return dist, prev


def shortest_path(
    graph: Dict[Hashable, List[Tuple[Hashable, float]]], start: Hashable, goal: Hashable
) -> Optional[List[Hashable]]:
    """Reconstruct shortest path, or None if unreachable."""
    dist, prev = dijkstra(graph, start)
    if goal not in dist:
        return None
    path = [goal]
    while prev[path[-1]] is not None:
        path.append(prev[path[-1]])  # type: ignore[arg-type]
    return path[::-1]


def test_dijkstra_basic():
    g = {"a": [("b", 1), ("c", 4)], "b": [("c", 2)], "c": []}
    dist, _ = dijkstra(g, "a")
    assert dist == {"a": 0.0, "b": 1.0, "c": 3.0}


def test_dijkstra_path():
    g = {"a": [("b", 1), ("c", 4)], "b": [("c", 2)], "c": []}
    assert shortest_path(g, "a", "c") == ["a", "b", "c"]


def test_dijkstra_unreachable():
    g = {"a": [("b", 1)], "b": [], "c": []}
    dist, _ = dijkstra(g, "a")
    assert "c" not in dist
    assert shortest_path(g, "a", "c") is None


def test_dijkstra_rejects_negative():
    g = {"a": [("b", -1)], "b": []}
    try:
        dijkstra(g, "a")
    except NegativeWeightError:
        return
    raise AssertionError("expected NegativeWeightError")


def test_dijkstra_single_node():
    dist, _ = dijkstra({"a": []}, "a")
    assert dist == {"a": 0.0}


def main() -> None:
    test_dijkstra_basic()
    test_dijkstra_path()
    test_dijkstra_unreachable()
    test_dijkstra_rejects_negative()
    test_dijkstra_single_node()
    print("graph_03 (Dijkstra) OK")


if __name__ == "__main__":
    main()
