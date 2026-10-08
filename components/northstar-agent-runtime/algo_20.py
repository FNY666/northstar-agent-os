"""A* shortest-path search.

Guided best-first search: expands nodes in order of f(n) = g(n) + h(n), where
g(n) is the known cost from ``start`` and ``heuristic(n)`` estimates the
remaining cost to ``goal``. ``graph`` maps each node to a dict of
neighbor -> edge weight. Returns the shortest path as a node list, or None
when ``goal`` is unreachable. ``start == goal`` returns ``[start]``. Raises
ValueError on negative edge weights.

Complexity: time O(E) to O(b^d) depending on heuristic quality; with an
admissible heuristic the returned path is optimal. Space O(V).
"""

import heapq
import itertools
from typing import Callable, Dict, Hashable, List, Optional

ALGO_20_VERSION = "algo-20.v1"

_STDLIB = frozenset({"typing", "heapq", "itertools"})


def a_star(
    graph: Dict[Hashable, Dict[Hashable, float]],
    start: Hashable,
    goal: Hashable,
    heuristic: Callable[[Hashable], float],
) -> Optional[List[Hashable]]:
    """Return the shortest node path from ``start`` to ``goal``, or None."""
    for node, neighbors in graph.items():
        for neighbor, weight in neighbors.items():
            if weight < 0:
                raise ValueError(
                    f"negative weight {weight!r} on edge {node!r}->{neighbor!r}"
                )
    if start == goal:
        return [start]
    counter = itertools.count()
    open_heap = [(heuristic(start), next(counter), 0.0, start)]
    g_score: Dict[Hashable, float] = {start: 0.0}
    came_from: Dict[Hashable, Hashable] = {}
    closed = set()
    while open_heap:
        _, _, g_cur, node = heapq.heappop(open_heap)
        if node in closed:
            continue
        if node == goal:
            path = [node]
            while node in came_from:
                node = came_from[node]
                path.append(node)
            return path[::-1]
        closed.add(node)
        for neighbor, weight in graph.get(node, {}).items():
            new_g = g_cur + weight
            if new_g < g_score.get(neighbor, float("inf")):
                g_score[neighbor] = new_g
                came_from[neighbor] = node
                heapq.heappush(
                    open_heap, (new_g + heuristic(neighbor), next(counter), new_g, neighbor)
                )
    return None


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
    h = {"s": 3, "a": 2, "b": 2, "t": 0}.__getitem__
    assert a_star(g, "s", "t", h) == ["s", "b", "a", "t"]
    assert a_star(g, "s", "s", h) == ["s"]
    assert a_star({"s": {"a": 1}, "a": {}, "z": {}}, "s", "z", lambda n: 0) is None
    try:
        a_star({"s": {"a": -2}, "a": {}}, "s", "a", lambda n: 0)
        raise AssertionError("expected ValueError for negative weight")
    except ValueError:
        pass
    stdlib_only()
    print("algo-20 OK")


if __name__ == "__main__":
    main()
