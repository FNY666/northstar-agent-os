"""graph_31: Single-source shortest path on a DAG (topo order). Stdlib only.

GRAPH_31_VERSION = graph-31.v1
"""
from __future__ import annotations

from collections import deque
from typing import Dict, Hashable, List, Optional, Tuple

GRAPH_31_VERSION = "graph-31.v1"


def _topo(graph: Dict[Hashable, List[Tuple[Hashable, float]]]) -> List[Hashable]:
    indeg: Dict[Hashable, int] = {u: 0 for u in graph}
    for u in graph:
        for v, _ in graph[u]:
            indeg[v] = indeg.get(v, 0) + 1
    q: deque = deque([u for u, d in indeg.items() if d == 0])
    order = []
    while q:
        u = q.popleft()
        order.append(u)
        for v, _ in graph.get(u, []):
            indeg[v] -= 1
            if indeg[v] == 0:
                q.append(v)
    if len(order) != len(indeg):
        raise ValueError("graph has a cycle")
    return order


def dag_shortest_path(
    graph: Dict[Hashable, List[Tuple[Hashable, float]]], start: Hashable
) -> Tuple[Dict[Hashable, float], Dict[Hashable, Optional[Hashable]]]:
    """O(V+E) shortest paths on DAG; handles negative weights (no neg cycles possible)."""
    order = _topo(graph)
    INF = float("inf")
    dist = {u: INF for u in indeg_nodes(graph)}
    prev: Dict[Hashable, Optional[Hashable]] = {u: None for u in dist}
    dist[start] = 0.0
    started = False
    for u in order:
        if u == start:
            started = True
        if not started:
            continue
        for v, w in graph.get(u, []):
            if dist[u] + w < dist[v]:
                dist[v] = dist[u] + w
                prev[v] = u
    return dist, prev


def indeg_nodes(graph: Dict[Hashable, List[Tuple[Hashable, float]]]) -> List[Hashable]:
    nodes = set(graph)
    for u in graph:
        for v, _ in graph[u]:
            nodes.add(v)
    return list(nodes)


def test_dag_sp_basic():
    g = {"a": [("b", 1), ("c", 4)], "b": [("c", -2)], "c": []}
    dist, _ = dag_shortest_path(g, "a")
    assert dist["c"] == -1.0


def test_dag_sp_negative():
    g = {"s": [("a", 5), ("b", 3)], "a": [("t", 2)], "b": [("a", -4), ("t", 6)], "t": []}
    dist, _ = dag_shortest_path(g, "s")
    assert dist["a"] == -1.0 and dist["t"] == 1.0


def test_dag_sp_unreachable():
    g = {"a": [("b", 1)], "b": [], "c": []}
    dist, _ = dag_shortest_path(g, "a")
    assert dist["c"] == float("inf")


def test_dag_sp_cycle_rejected():
    g = {"a": [("b", 1)], "b": [("a", 1)]}
    try:
        dag_shortest_path(g, "a")
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_dag_sp_single():
    dist, _ = dag_shortest_path({"a": []}, "a")
    assert dist == {"a": 0.0}


def main() -> None:
    test_dag_sp_basic()
    test_dag_sp_negative()
    test_dag_sp_unreachable()
    test_dag_sp_cycle_rejected()
    test_dag_sp_single()
    print("graph_31 (DAG shortest path) OK")


if __name__ == "__main__":
    main()
