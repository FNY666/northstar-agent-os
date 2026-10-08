"""DFS graph search, Simulated.

What this IS: path finding with O(V) memory via iterative deepening stack.

What this IS NOT: path is not shortest; use BFS for fewest edges.
"""

from __future__ import annotations

import ast
from typing import Dict, List, Optional

#: Module version.
SEARCH_17_VERSION = "search-17.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.search-17.v1"


class SearchError(Exception):
    """Fail-closed."""


def dfs_path(graph: Dict[str, List[str]], start: str, goal: str) -> Optional[List[str]]:
    """A path from start to goal, or None. Cycle-safe."""
    if graph is None:
        raise SearchError("graph required")
    stack = [(start, [start])]
    seen = set()
    while stack:
        node, path = stack.pop()
        if node == goal:
            return path
        if node in seen:
            continue
        seen.add(node)
        for nb in reversed(graph.get(node, [])):
            if nb not in seen:
                stack.append((nb, path + [nb]))
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
    p = dfs_path(g, "a", "d")
    assert p[0] == "a" and p[-1] == "d"
    assert dfs_path(g, "a", "z") is None
    assert stdlib_only()
    print("search-17.v1 OK")


if __name__ == "__main__":
    main()
