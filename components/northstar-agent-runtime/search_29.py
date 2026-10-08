"""Uniform-cost search, Simulated.

What this IS: Dijkstra returning the cheapest path and its cost.

What this IS NOT: not for negative weights; needs non-negative costs.
"""

from __future__ import annotations

import ast
import heapq
from typing import Dict, List, Optional, Tuple

#: Module version.
SEARCH_29_VERSION = "search-29.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.search-29.v1"


class SearchError(Exception):
    """Fail-closed."""


def uniform_cost_search(graph: Dict[str, List[Tuple[str, float]]], start: str,
                        goal: str) -> Tuple[Optional[List[str]], float]:
    """(cheapest path, cost); (None, inf) if unreachable."""
    if graph is None:
        raise SearchError("graph required")
    pq = [(0, start, [start])]
    best: Dict[str, float] = {}
    while pq:
        cost, node, path = heapq.heappop(pq)
        if node == goal:
            return path, cost
        if node in best and best[node] <= cost:
            continue
        best[node] = cost
        for nb, w in graph.get(node, []):
            heapq.heappush(pq, (cost + w, nb, path + [nb]))
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
    g = {"a": [("b", 10), ("c", 1)], "b": [("d", 1)], "c": [("d", 10)], "d": []}
    p, c = uniform_cost_search(g, "a", "d")
    assert p == ["a", "b", "d"] and c == 11
    p2, c2 = uniform_cost_search(g, "a", "z")
    assert p2 is None
    assert stdlib_only()
    print("search-29.v1 OK")


if __name__ == "__main__":
    main()
