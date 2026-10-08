"""Bellman-Ford single-source shortest paths.

Relaxes all edges V-1 times; a further pass detects negative-weight cycles
reachable from the source and raises ValueError in that case.

Time complexity: O(V * E). Space: O(V).
Handles negative edge weights (unlike Dijkstra). Unreachable nodes get
distance float("inf").
"""

from typing import Dict

ALGO_24_VERSION = "algo-24.v1"

_STDLIB_USED = {"typing", "ast", "pathlib"}

_INF = float("inf")


def _iter_edges(graph):
    for u, adj in graph.items():
        if isinstance(adj, dict):
            for v, w in adj.items():
                yield u, v, w
        else:
            for v, w in adj:  # list of (neighbor, weight) pairs
                yield u, v, w


def bellman_ford(graph: Dict, start) -> Dict:
    """Return dict node -> shortest distance from ``start``.

    ``graph`` is dict node -> dict neighbor -> weight (or node -> list of
    (neighbor, weight) pairs). Raises ValueError if a negative-weight cycle
    reachable from ``start`` exists.
    """
    dist = {node: _INF for node in graph}
    dist.setdefault(start, _INF)
    for _u, adj in graph.items():
        nbrs = adj.keys() if isinstance(adj, dict) else [v for v, _w in adj]
        for v in nbrs:
            dist.setdefault(v, _INF)
    dist[start] = 0
    nodes = list(dist)
    edges = list(_iter_edges(graph))
    for _ in range(len(nodes) - 1):
        updated = False
        for u, v, w in edges:
            if dist[u] != _INF and dist[u] + w < dist[v]:
                dist[v] = dist[u] + w
                updated = True
        if not updated:
            break
    for u, v, w in edges:
        if dist[u] != _INF and dist[u] + w < dist[v]:
            raise ValueError("negative-weight cycle reachable from source")
    return dist


def stdlib_only() -> bool:
    """Assert every imported top-level module is one actually used from the stdlib."""
    import ast
    from pathlib import Path

    tree = ast.parse(Path(__file__).read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    assert imported <= _STDLIB_USED, f"non-stdlib/unused import: {imported - _STDLIB_USED}"
    return True


def main() -> None:
    g = {"S": {"A": 4, "B": 2}, "A": {"T": 3}, "B": {"A": 1, "T": 5}, "T": {}}
    d = bellman_ford(g, "S")
    assert d == {"S": 0, "A": 3, "B": 2, "T": 6}, d
    d2 = bellman_ford({"A": {"B": -2}, "B": {}}, "A")
    assert d2 == {"A": 0, "B": -2}, d2
    d3 = bellman_ford({"A": {}, "B": {}}, "A")
    assert d3["B"] == float("inf") and d3["A"] == 0
    d4 = bellman_ford({"X": [("Y", 5)], "Y": []}, "X")  # pair-list format
    assert d4 == {"X": 0, "Y": 5}, d4
    try:
        bellman_ford({"A": {"B": -1}, "B": {"A": -1}}, "A")
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError on negative cycle")
    assert stdlib_only() is True
    print("algo_24 OK")


if __name__ == "__main__":
    main()
