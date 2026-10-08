"""Iterative deepening DFS, Simulated.

What this IS: DFS with growing depth limit; optimal like BFS, memory like DFS.

What this IS NOT: re-expands upper levels; slower than BFS on wide trees.
"""

from __future__ import annotations

import ast
from typing import Dict, List, Optional

#: Module version.
SEARCH_21_VERSION = "search-21.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.search-21.v1"


class SearchError(Exception):
    """Fail-closed."""


def _dls(graph: Dict[str, List[str]], node: str, goal: str,
         limit: int, seen: set) -> Optional[List[str]]:
    if node == goal:
        return [node]
    if limit == 0:
        return None
    seen.add(node)
    for nb in graph.get(node, []):
        if nb in seen:
            continue
        res = _dls(graph, nb, goal, limit - 1, seen)
        if res:
            return [node] + res
    seen.discard(node)
    return None


def iddfs(graph: Dict[str, List[str]], start: str, goal: str,
          max_depth: int) -> Optional[List[str]]:
    """Shallowest path within max_depth, or None."""
    if graph is None:
        raise SearchError("graph required")
    if max_depth < 0:
        raise SearchError("max_depth must be >= 0")
    for depth in range(max_depth + 1):
        res = _dls(graph, start, goal, depth, set())
        if res:
            return res
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
    chain = {"a": ["b"], "b": ["c"], "c": ["d"], "d": []}
    assert iddfs(chain, "a", "d", 3) == ["a", "b", "c", "d"]
    assert iddfs(chain, "a", "d", 2) is None
    assert stdlib_only()
    print("search-21.v1 OK")


if __name__ == "__main__":
    main()
