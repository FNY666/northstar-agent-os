"""bfs_limited: nodes reachable within max_depth hops of start via BFS. IS: a sorted node list within depth; negative depth raises ValueError. IS NOT: a depth-first depth-limited search."""

from __future__ import annotations

import ast
from collections import deque
from typing import Dict, Hashable, List
VERSION = "queue-22.v1"

def bfs_limited(graph: Dict[Hashable, List[Hashable]],
                 start: Hashable, max_depth: int) -> List[Hashable]:
    """Return sorted nodes with BFS distance from ``start`` <= ``max_depth``."""
    if not isinstance(graph, dict):
        raise ValueError("graph must be a dict")
    if isinstance(max_depth, bool) or not isinstance(max_depth, int) or max_depth < 0:
        raise ValueError("max_depth must be a non-negative int")
    if start not in graph:
        return []
    seen = {start}
    q: deque = deque([(start, 0)])
    while q:
        node, d = q.popleft()
        if d == max_depth:
            continue
        for nb in graph.get(node, []):
            if nb not in seen:
                seen.add(nb)
                q.append((nb, d + 1))
    return sorted(seen)


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
    g = {"A": ["B", "C"], "B": ["D"], "C": ["D"], "D": ["E"], "E": []}
    assert bfs_limited(g, "A", 0) == ["A"]
    assert bfs_limited(g, "A", 1) == ["A", "B", "C"]
    assert bfs_limited(g, "A", 2) == ["A", "B", "C", "D"]
    assert bfs_limited(g, "A", 9) == ["A", "B", "C", "D", "E"]
    assert bfs_limited(g, "Z", 3) == []
    try:
        bfs_limited(g, "A", -1)
    except ValueError:
        pass
    else:
        raise AssertionError("negative depth must raise ValueError")
    assert stdlib_only()
    print("queue-22 OK: depth-limited BFS")


if __name__ == "__main__":
    main()
