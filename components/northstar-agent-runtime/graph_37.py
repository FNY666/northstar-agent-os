"""graph_37: Johnson's all-pairs shortest paths. Standard library only.

GRAPH_37_VERSION = graph-37.v1
"""
from __future__ import annotations

import heapq
from typing import Dict, Hashable, List, Tuple

GRAPH_37_VERSION = "graph-37.v1"


class NegativeCycleError(ValueError):
    pass


def johnson(
    nodes: List[Hashable], edges: List[Tuple[Hashable, Hashable, float]]
) -> Dict[Hashable, Dict[Hashable, float]]:
    """All-pairs shortest paths; handles negative weights, no negative cycles."""
    INF = float("inf")
    # Bellman-Ford from super source for potentials
    h = {u: 0.0 for u in nodes}
    for _ in range(len(nodes) - 1):
        updated = False
        for u, v, w in edges:
            if h[u] + w < h[v]:
                h[v] = h[u] + w
                updated = True
        if not updated:
            break
    for u, v, w in edges:
        if h[u] + w < h[v]:
            raise NegativeCycleError("negative cycle")
    adj: Dict[Hashable, List[Tuple[Hashable, float]]] = {u: [] for u in nodes}
    for u, v, w in edges:
        adj[u].append((v, w + h[u] - h[v]))  # non-negative reweight
    result: Dict[Hashable, Dict[Hashable, float]] = {}
    for s in nodes:
        dist = {u: INF for u in nodes}
        dist[s] = 0.0
        pq: List[Tuple[float, Hashable]] = [(0.0, s)]
        done = set()
        while pq:
            d, u = heapq.heappop(pq)
            if u in done:
                continue
            done.add(u)
            for v, w in adj[u]:
                nd = d + w
                if nd < dist[v]:
                    dist[v] = nd
                    heapq.heappush(pq, (nd, v))
        result[s] = {v: (dist[v] - h[s] + h[v] if dist[v] != INF else INF) for v in nodes}
    return result


def test_johnson_basic():
    nodes = ["a", "b", "c"]
    edges = [("a", "b", 1), ("b", "c", 2), ("a", "c", 10)]
    d = johnson(nodes, edges)
    assert d["a"]["c"] == 3.0 and d["a"]["a"] == 0.0


def test_johnson_negative_edge():
    nodes = ["a", "b", "c"]
    edges = [("a", "b", 2), ("b", "c", -1), ("a", "c", 5)]
    d = johnson(nodes, edges)
    assert d["a"]["c"] == 1.0 and d["b"]["c"] == -1.0


def test_johnson_agrees_with_floyd():
    import sys
    sys.path.insert(0, __file__.rsplit("/", 1)[0])
    import graph_05

    nodes = ["a", "b", "c", "d"]
    edges = [("a", "b", 3), ("b", "c", -2), ("c", "d", 4), ("a", "d", 9), ("b", "d", 1)]
    dj = johnson(nodes, edges)
    df, _ = graph_05.floyd_warshall(nodes, edges)
    for u in nodes:
        for v in nodes:
            assert abs(dj[u][v] - df[u][v]) < 1e-9


def test_johnson_negative_cycle():
    nodes = ["a", "b"]
    edges = [("a", "b", 1), ("b", "a", -3)]
    try:
        johnson(nodes, edges)
    except NegativeCycleError:
        return
    raise AssertionError("expected NegativeCycleError")


def test_johnson_single():
    assert johnson(["a"], []) == {"a": {"a": 0.0}}


def main() -> None:
    test_johnson_basic()
    test_johnson_negative_edge()
    test_johnson_agrees_with_floyd()
    test_johnson_negative_cycle()
    test_johnson_single()
    print("graph_37 (Johnson) OK")


if __name__ == "__main__":
    main()
