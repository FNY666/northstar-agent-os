"""BFS graph search, Simulated.

What this IS: shortest path (fewest edges) in unweighted graphs.

What this IS NOT: not for weighted graphs; use Dijkstra there.
"""

from __future__ import annotations

import ast
from collections import deque
from typing import Dict, List, Optional

#: Module version.
SEARCH_16_VERSION = "search-16.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.search-16.v1"


class SearchError(Exception):
    """Fail-closed."""


def bfs_path(graph: Dict[str, List[str]], start: str, goal: str) -> Optional[List[str]]:
    """Shortest path from start to goal, or None."""
    if graph is None:
        raise SearchError("graph required")
    if start == goal:
        return [start]
    queue = deque([(start, [start])])
    seen = {start}
    while queue:
        node, path = queue.popleft()
        for nb in graph.get(node, []):
            if nb in seen:
                continue
            if nb == goal:
                return path + [nb]
            seen.add(nb)
            queue.append((nb, path + [nb]))
    return None

def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "collections", "dataclasses", "heapq",
               "itertools", "math", "pathlib", "random", "typing"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    """Self-check."""
    g = {"a": ["b", "c"], "b": ["d"], "c": ["d"], "d": []}
    assert bfs_path(g, "a", "d") == ["a", "b", "d"]
    assert bfs_path(g, "a", "z") is None
    assert bfs_path(g, "a", "a") == ["a"]
    assert stdlib_only()
    print("search-16.v1 OK")


if __name__ == "__main__":
    main()
