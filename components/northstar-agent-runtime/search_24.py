"""Bellman-Ford, Simulated.

What this IS: shortest paths with negative edges; detects negative cycles.

What this IS NOT: slower than Dijkstra; needs no negative cycle to succeed.
"""

from __future__ import annotations

import ast
import math
from typing import Dict, List, Tuple

#: Module version.
SEARCH_24_VERSION = "search-24.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.search-24.v1"


class SearchError(Exception):
    """Fail-closed."""


def bellman_ford(graph: Dict[str, List[Tuple[str, float]]],
                 start: str) -> Dict[str, float]:
    """Shortest distances; raises SearchError on negative cycle."""
    if graph is None:
        raise SearchError("graph required")
    nodes = set(graph)
    for u in graph:
        for v, _ in graph[u]:
            nodes.add(v)
    dist = {n: math.inf for n in nodes}
    dist[start] = 0
    for _ in range(len(nodes) - 1):
        updated = False
        for u in graph:
            for v, w in graph[u]:
                if dist[u] + w < dist[v]:
                    dist[v] = dist[u] + w
                    updated = True
        if not updated:
            break
    for u in graph:
        for v, w in graph[u]:
            if dist[u] + w < dist[v]:
                raise SearchError("negative cycle")
    return dist

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
    g = {"a": [("b", -2)], "b": [("c", 3)], "c": []}
    assert bellman_ford(g, "a")["c"] == 1
    bad = {"a": [("b", 1)], "b": [("a", -2)]}
    try:
        bellman_ford(bad, "a")
        assert False
    except SearchError:
        pass
    assert stdlib_only()
    print("search-24.v1 OK")


if __name__ == "__main__":
    main()
