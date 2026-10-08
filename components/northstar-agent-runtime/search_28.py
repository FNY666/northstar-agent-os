"""Greedy best-first search, Simulated.

What this IS: expands the node closest to the goal by heuristic alone.

What this IS NOT: not optimal and not complete on graphs with dead ends.
"""

from __future__ import annotations

import ast
import heapq
from typing import Callable, Dict, List, Optional

#: Module version.
SEARCH_28_VERSION = "search-28.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.search-28.v1"


class SearchError(Exception):
    """Fail-closed."""


def greedy_best_first(graph: Dict[str, List[str]], start: str, goal: str,
                      heuristic: Callable[[str], float],
                      max_iters: int = 10000) -> Optional[List[str]]:
    """Heuristic-only path to goal, or None."""
    if graph is None or heuristic is None:
        raise SearchError("args required")
    openh = [(heuristic(start), [start])]
    iters = 0
    while openh and iters < max_iters:
        iters += 1
        _, path = heapq.heappop(openh)
        node = path[-1]
        if node == goal:
            return path
        for nb in graph.get(node, []):
            if nb not in path:
                heapq.heappush(openh, (heuristic(nb), path + [nb]))
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
    g = {"s": ["a", "b"], "a": ["g"], "b": ["g"], "g": []}
    h = {"s": 3, "a": 1, "b": 5, "g": 0}.__getitem__
    assert greedy_best_first(g, "s", "g", h) == ["s", "a", "g"]
    assert stdlib_only()
    print("search-28.v1 OK")


if __name__ == "__main__":
    main()
