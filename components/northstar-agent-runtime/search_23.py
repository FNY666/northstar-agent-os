"""Dijkstra shortest path, Simulated.

What this IS: O(E log V) shortest paths for non-negative weights.

What this IS NOT: fails on negative weights; use Bellman-Ford there.
"""

from __future__ import annotations

import ast
import heapq
import math
from typing import Dict, List, Tuple

#: Module version.
SEARCH_23_VERSION = "search-23.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.search-23.v1"


class SearchError(Exception):
    """Fail-closed."""


def dijkstra(graph: Dict[str, List[Tuple[str, float]]],
             start: str) -> Dict[str, float]:
    """Shortest distances from start; unreachable -> math.inf."""
    if graph is None:
        raise SearchError("graph required")
    dist = {n: math.inf for n in graph}
    dist[start] = 0
    pq = [(0, start)]
    while pq:
        d, u = heapq.heappop(pq)
        if d > dist.get(u, math.inf):
            continue
        for v, w in graph.get(u, []):
            nd = d + w
            if nd < dist.get(v, math.inf):
                dist[v] = nd
                heapq.heappush(pq, (nd, v))
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
    g = {"a": [("b", 1), ("c", 4)], "b": [("c", 2), ("d", 5)],
         "c": [("d", 1)], "d": []}
    d = dijkstra(g, "a")
    assert d["d"] == 4 and d["a"] == 0
    assert stdlib_only()
    print("search-23.v1 OK")


if __name__ == "__main__":
    main()
