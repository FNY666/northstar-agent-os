"""bfs_order: breadth-first visit order of a graph from a start node. IS: a BFS order list; unknown start yields []; non-dict graph raises ValueError. IS NOT: a DFS order or a shortest-path tree."""

from __future__ import annotations

import ast
from collections import deque
from typing import Any, Dict, Hashable, List
VERSION = "queue-11.v1"

def _req_graph(graph: object) -> Dict[Hashable, List[Hashable]]:
    if not isinstance(graph, dict):
        raise ValueError("graph must be a dict of node -> neighbor list")
    for node, nbrs in graph.items():
        if not isinstance(nbrs, list):
            raise ValueError("each neighbor list must be a list")
    return graph


def bfs_order(graph: Dict[Hashable, List[Hashable]], start: Hashable) -> List[Hashable]:
    """Return nodes in BFS order starting at ``start``."""
    graph = _req_graph(graph)
    if start not in graph:
        return []
    seen = {start}
    q: deque = deque([start])
    order: List[Hashable] = []
    while q:
        node = q.popleft()
        order.append(node)
        for nb in graph[node]:
            if nb not in seen:
                seen.add(nb)
                q.append(nb)
    return order


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
    g = {"A": ["B", "C"], "B": ["D"], "C": ["D"], "D": [], "Z": []}
    assert bfs_order(g, "A") == ["A", "B", "C", "D"]
    assert bfs_order(g, "Z") == ["Z"]
    assert bfs_order(g, "Q") == []
    assert bfs_order({}, "A") == []
    try:
        bfs_order([("A", [])], "A")
    except ValueError:
        pass
    else:
        raise AssertionError("non-dict graph must raise ValueError")
    try:
        bfs_order({"A": "BC"}, "A")
    except ValueError:
        pass
    else:
        raise AssertionError("non-list neighbors must raise ValueError")
    assert stdlib_only()
    print("queue-11 OK: BFS visit order")


if __name__ == "__main__":
    main()
