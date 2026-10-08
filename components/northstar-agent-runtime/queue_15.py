"""bfs_shortest_path: shortest path between two nodes in an unweighted graph via BFS. IS: a shortest node path or []; unknown endpoints yield []. IS NOT: a weighted shortest path or all-pairs distances."""

from __future__ import annotations

import ast
from collections import deque
from typing import Dict, Hashable, List
VERSION = "queue-15.v1"

def bfs_shortest_path(graph: Dict[Hashable, List[Hashable]],
                      start: Hashable, goal: Hashable) -> List[Hashable]:
    """Return one shortest path from ``start`` to ``goal`` (inclusive)."""
    if not isinstance(graph, dict):
        raise ValueError("graph must be a dict")
    if start not in graph or goal not in graph:
        return []
    if start == goal:
        return [start]
    prev: Dict[Hashable, Hashable] = {}
    q: deque = deque([start])
    seen = {start}
    while q:
        node = q.popleft()
        for nb in graph.get(node, []):
            if nb not in seen:
                seen.add(nb)
                prev[nb] = node
                if nb == goal:
                    path = [goal]
                    while path[-1] != start:
                        path.append(prev[path[-1]])
                    return path[::-1]
                q.append(nb)
    return []


def stdlib_only() -> bool:
    """AST-check: every import in this file resolves to the standard library."""
    import pathlib

    allowed = {"__future__", "ast", "pathlib", "typing", "collections"}
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if (node.module or "").split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    g = {"A": ["B", "C"], "B": ["D"], "C": ["D"], "D": []}
    p = bfs_shortest_path(g, "A", "D")
    assert p in (["A", "B", "D"], ["A", "C", "D"]) and len(p) == 3
    line = {"A": ["B"], "B": ["C"], "C": ["D"], "D": []}
    assert bfs_shortest_path(line, "A", "D") == ["A", "B", "C", "D"]
    assert bfs_shortest_path(line, "D", "A") == []
    assert bfs_shortest_path(line, "A", "A") == ["A"]
    assert bfs_shortest_path(line, "A", "Z") == []
    try:
        bfs_shortest_path([], "A", "B")
    except ValueError:
        pass
    else:
        raise AssertionError("non-dict graph must raise ValueError")
    assert stdlib_only()
    print("queue-15 OK: BFS shortest path")


if __name__ == "__main__":
    main()
