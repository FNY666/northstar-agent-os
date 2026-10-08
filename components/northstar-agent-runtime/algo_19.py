"""Dijkstra's shortest-path algorithm.

Computes the shortest distance from ``start`` to every node using a binary
heap (heapq). ``graph`` maps each node to a dict of neighbor -> edge weight.
Nodes unreachable from ``start`` get distance float("inf"). Raises
ValueError if any edge weight is negative (Dijkstra requires non-negative
weights).

Complexity: time O((V + E) log V), space O(V).
"""

import heapq
from typing import Dict, Hashable

ALGO_19_VERSION = "algo-19.v1"

_STDLIB = frozenset({"typing", "heapq"})


def dijkstra(
    graph: Dict[Hashable, Dict[Hashable, float]], start: Hashable
) -> Dict[Hashable, float]:
    """Return the shortest distance from ``start`` to every known node."""
    for node, neighbors in graph.items():
        for neighbor, weight in neighbors.items():
            if weight < 0:
                raise ValueError(
                    f"negative weight {weight!r} on edge {node!r}->{neighbor!r}"
                )
    dist: Dict[Hashable, float] = {node: float("inf") for node in graph}
    if start not in graph:
        return dist
    dist[start] = 0.0
    heap = [(0.0, start)]
    while heap:
        d, node = heapq.heappop(heap)
        if d > dist[node]:
            continue
        for neighbor, weight in graph.get(node, {}).items():
            new_d = d + weight
            if new_d < dist.get(neighbor, float("inf")):
                dist[neighbor] = new_d
                heapq.heappush(heap, (new_d, neighbor))
    return dist


def stdlib_only() -> None:
    """Parse this file with ast; assert all module-level imports are used stdlib."""
    import ast
    from pathlib import Path

    tree = ast.parse(Path(__file__).read_text(encoding="utf-8"))
    imported = {}
    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                top = alias.name.split(".")[0]
                imported.setdefault(top, set()).add((alias.asname or top).split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.level == 0:
                top = node.module.split(".")[0]
                for alias in node.names:
                    imported.setdefault(top, set()).add(alias.asname or alias.name)
    assert set(imported) <= _STDLIB, f"non-stdlib imports: {set(imported) - _STDLIB}"
    used = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
    for mod, names in imported.items():
        for name in names:
            assert name in used, f"imported but unused: {name} (from {mod})"


def main() -> None:
    g = {"s": {"a": 4, "b": 2}, "a": {"t": 1}, "b": {"a": 1, "t": 5}, "t": {}}
    d = dijkstra(g, "s")
    assert d == {"s": 0.0, "a": 3.0, "b": 2.0, "t": 4.0}, d
    d2 = dijkstra({"s": {}, "x": {}}, "s")
    assert d2["s"] == 0.0 and d2["x"] == float("inf")
    try:
        dijkstra({"s": {"a": -1}}, "s")
        raise AssertionError("expected ValueError for negative weight")
    except ValueError:
        pass
    d3 = dijkstra({"only": {}}, "only")
    assert d3 == {"only": 0.0}
    stdlib_only()
    print("algo-19 OK")


if __name__ == "__main__":
    main()
