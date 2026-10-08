"""graph_32: Longest path on a DAG (critical path). Standard library only.

GRAPH_32_VERSION = graph-32.v1
"""
from __future__ import annotations

from collections import deque
from typing import Dict, Hashable, List, Optional, Tuple

GRAPH_32_VERSION = "graph-32.v1"


def dag_longest_path(
    graph: Dict[Hashable, List[Tuple[Hashable, float]]], start: Hashable
) -> Tuple[Dict[Hashable, float], Optional[List[Hashable]]]:
    """Longest distances from start + one longest path to the farthest node."""
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
    NEG = float("-inf")
    dist = {u: NEG for u in indeg}
    prev: Dict[Hashable, Optional[Hashable]] = {u: None for u in indeg}
    dist[start] = 0.0
    started = False
    for u in order:
        if u == start:
            started = True
        if not started or dist[u] == NEG:
            continue
        for v, w in graph.get(u, []):
            if dist[u] + w > dist[v]:
                dist[v] = dist[u] + w
                prev[v] = u
    far = max((u for u in dist if dist[u] != NEG), key=lambda u: dist[u], default=start)
    path = [far]
    while prev[path[-1]] is not None:
        path.append(prev[path[-1]])  # type: ignore[arg-type]
    return dist, path[::-1]


def test_dag_lp_basic():
    g = {"a": [("b", 3), ("c", 2)], "b": [("d", 4)], "c": [("d", 1)], "d": []}
    dist, path = dag_longest_path(g, "a")
    assert dist["d"] == 7.0 and path == ["a", "b", "d"]


def test_dag_lp_negative_weights():
    g = {"a": [("b", -1), ("c", 5)], "b": [("c", 10)], "c": []}
    dist, path = dag_longest_path(g, "a")
    assert dist["c"] == 9.0 and path == ["a", "b", "c"]


def test_dag_lp_single():
    dist, path = dag_longest_path({"a": []}, "a")
    assert dist == {"a": 0.0} and path == ["a"]


def test_dag_lp_unreachable_ignored():
    g = {"a": [("b", 2)], "b": [], "z": [("z2", 99)], "z2": []}
    dist, path = dag_longest_path(g, "a")
    assert dist["b"] == 2.0 and path[-1] == "b"


def test_dag_lp_chain():
    g = {"a": [("b", 1)], "b": [("c", 1)], "c": [("d", 1)], "d": []}
    dist, path = dag_longest_path(g, "a")
    assert dist["d"] == 3.0 and path == ["a", "b", "c", "d"]


def main() -> None:
    test_dag_lp_basic()
    test_dag_lp_negative_weights()
    test_dag_lp_single()
    test_dag_lp_unreachable_ignored()
    test_dag_lp_chain()
    print("graph_32 (DAG longest path) OK")


if __name__ == "__main__":
    main()
