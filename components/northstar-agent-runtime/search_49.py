"""A* graph search, Simulated.

What this IS: optimal weighted-graph path with an admissible heuristic.

What this IS NOT: heuristic must not overestimate; else use Dijkstra.
"""

from __future__ import annotations

import ast
import heapq
from typing import Callable, Dict, List, Optional, Tuple

#: Module version.
SEARCH_49_VERSION = "search-49.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.search-49.v1"


class SearchError(Exception):
    """Fail-closed."""


def a_star_graph(graph: Dict[str, List[Tuple[str, float]]], start: str,
                 goal: str,
                 heuristic: Callable[[str], float]) -> Tuple[Optional[List[str]], float]:
    """(optimal path, cost); (None, inf) if unreachable."""
    if graph is None or heuristic is None:
        raise SearchError("args required")
    openh = [(heuristic(start), 0, start, [start])]
    best: Dict[str, float] = {}
    while openh:
        _, g, node, path = heapq.heappop(openh)
        if node == goal:
            return path, g
        if node in best and best[node] <= g:
            continue
        best[node] = g
        for nb, w in graph.get(node, []):
            ng = g + w
            heapq.heappush(openh, (ng + heuristic(nb), ng, nb, path + [nb]))
    return None, float("inf")

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
    g = {"s": [("a", 1), ("b", 4)], "a": [("g", 5)], "b": [("g", 1)], "g": []}
    h = {"s": 3, "a": 2, "b": 1, "g": 0}.__getitem__
    p, c = a_star_graph(g, "s", "g", h)
    assert p == ["s", "b", "g"] and c == 5
    assert stdlib_only()
    print("search-49.v1 OK")


if __name__ == "__main__":
    main()
