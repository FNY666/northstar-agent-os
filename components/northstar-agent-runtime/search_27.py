"""Best-first search, Simulated.

What this IS: graph search ordered by f = g + h with a host heuristic.

What this IS NOT: not optimal unless h is admissible; not Dijkstra.
"""

from __future__ import annotations

import ast
import heapq
from typing import Callable, Dict, List, Optional

#: Module version.
SEARCH_27_VERSION = "search-27.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.search-27.v1"


class SearchError(Exception):
    """Fail-closed."""


def best_first_search(graph: Dict[str, List[str]], start: str, goal: str,
                      heuristic: Callable[[str], float]) -> Optional[List[str]]:
    """Path from start to goal ordered by f = g + h, or None."""
    if graph is None or heuristic is None:
        raise SearchError("args required")
    openh = [(heuristic(start), 0, [start])]
    seen = set()
    while openh:
        _, g, path = heapq.heappop(openh)
        node = path[-1]
        if node == goal:
            return path
        if node in seen:
            continue
        seen.add(node)
        for nb in graph.get(node, []):
            if nb not in seen:
                heapq.heappush(openh, (g + 1 + heuristic(nb), g + 1, path + [nb]))
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
    h = {"a": 2, "b": 1, "c": 1, "d": 0}.__getitem__
    p = best_first_search(g, "a", "d", h)
    assert p[0] == "a" and p[-1] == "d"
    assert best_first_search(g, "a", "z", h) is None
    assert stdlib_only()
    print("search-27.v1 OK")


if __name__ == "__main__":
    main()
