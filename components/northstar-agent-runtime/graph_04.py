"""graph_04: Bellman-Ford shortest paths with negative-cycle detection. Stdlib only.

GRAPH_04_VERSION = graph-04.v1
"""
from __future__ import annotations

from typing import Dict, Hashable, List, Optional, Tuple

GRAPH_04_VERSION = "graph-04.v1"


class NegativeCycleError(ValueError):
    """Raised when a reachable negative cycle exists."""


def bellman_ford(
    edges: List[Tuple[Hashable, Hashable, float]], nodes: List[Hashable], start: Hashable
) -> Tuple[Dict[Hashable, float], Dict[Hashable, Optional[Hashable]]]:
    """Returns (distances, predecessors). Raises NegativeCycleError."""
    INF = float("inf")
    dist = {n: INF for n in nodes}
    prev: Dict[Hashable, Optional[Hashable]] = {n: None for n in nodes}
    dist[start] = 0.0
    for _ in range(len(nodes) - 1):
        updated = False
        for u, v, w in edges:
            if dist[u] + w < dist[v]:
                dist[v] = dist[u] + w
                prev[v] = u
                updated = True
        if not updated:
            break
    for u, v, w in edges:
        if dist[u] + w < dist[v]:
            raise NegativeCycleError("reachable negative cycle detected")
    return dist, prev


def test_bellman_ford_basic():
    edges = [("a", "b", 1), ("b", "c", 2), ("a", "c", 5)]
    dist, _ = bellman_ford(edges, ["a", "b", "c"], "a")
    assert dist == {"a": 0.0, "b": 1.0, "c": 3.0}


def test_bellman_ford_negative_edge():
    edges = [("a", "b", 4), ("a", "c", 5), ("c", "b", -3)]
    dist, _ = bellman_ford(edges, ["a", "b", "c"], "a")
    assert dist["b"] == 2.0


def test_bellman_ford_negative_cycle():
    edges = [("a", "b", 1), ("b", "c", -5), ("c", "a", 1)]
    try:
        bellman_ford(edges, ["a", "b", "c"], "a")
    except NegativeCycleError:
        return
    raise AssertionError("expected NegativeCycleError")


def test_bellman_ford_unreachable():
    edges = [("a", "b", 1)]
    dist, _ = bellman_ford(edges, ["a", "b", "c"], "a")
    assert dist["c"] == float("inf")


def test_bellman_ford_no_false_cycle():
    edges = [("a", "b", 1), ("b", "a", 1)]
    dist, _ = bellman_ford(edges, ["a", "b"], "a")
    assert dist["b"] == 1.0


def main() -> None:
    test_bellman_ford_basic()
    test_bellman_ford_negative_edge()
    test_bellman_ford_negative_cycle()
    test_bellman_ford_unreachable()
    test_bellman_ford_no_false_cycle()
    print("graph_04 (Bellman-Ford) OK")


if __name__ == "__main__":
    main()
