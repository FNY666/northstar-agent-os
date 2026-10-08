"""Bidirectional Dijkstra, Simulated.

What this IS: two-ended Dijkstra; same result, often fewer expansions.

What this IS NOT: needs reverse edges; plain Dijkstra if unavailable.
"""

from __future__ import annotations

import ast
import heapq
import math
from typing import Dict, List, Optional, Tuple

#: Module version.
SEARCH_50_VERSION = "search-50.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.search-50.v1"


class SearchError(Exception):
    """Fail-closed."""


def bidirectional_dijkstra(graph: Dict[str, List[Tuple[str, float]]],
                          start: str, goal: str) -> Optional[float]:
    """Shortest distance; None if unreachable; 0 if start == goal."""
    if graph is None:
        raise SearchError("graph required")
    if start == goal:
        return 0
    rev: Dict[str, List[Tuple[str, float]]] = {}
    for u in graph:
        for v, w in graph[u]:
            rev.setdefault(v, []).append((u, w))
    df, db = {start: 0.0}, {goal: 0.0}
    qf, qb = [(0.0, start)], [(0.0, goal)]
    best = math.inf
    while qf and qb:
        if qf[0][0] + qb[0][0] >= best:
            break
        d, u = heapq.heappop(qf)
        if d > df.get(u, math.inf):
            continue
        for v, w in graph.get(u, []):
            nd = d + w
            if nd < df.get(v, math.inf):
                df[v] = nd
                heapq.heappush(qf, (nd, v))
                if v in db:
                    best = min(best, nd + db[v])
        d, u = heapq.heappop(qb)
        if d > db.get(u, math.inf):
            continue
        for v, w in rev.get(u, []):
            nd = d + w
            if nd < db.get(v, math.inf):
                db[v] = nd
                heapq.heappush(qb, (nd, v))
                if v in df:
                    best = min(best, nd + df[v])
    return best if best != math.inf else None

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
    assert bidirectional_dijkstra(g, "a", "d") == 4
    assert bidirectional_dijkstra(g, "a", "a") == 0
    assert bidirectional_dijkstra({"a": []}, "a", "z") is None
    assert stdlib_only()
    print("search-50.v1 OK")


if __name__ == "__main__":
    main()
