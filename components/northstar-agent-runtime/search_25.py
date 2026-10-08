"""Floyd-Warshall, Simulated.

What this IS: all-pairs shortest paths in O(V^3); handles negative edges.

What this IS NOT: needs no negative cycle; slow on large graphs.
"""

from __future__ import annotations

import ast
import math
from typing import Dict, List, Tuple

#: Module version.
SEARCH_25_VERSION = "search-25.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.search-25.v1"


class SearchError(Exception):
    """Fail-closed."""


def floyd_warshall(nodes: List[str],
                   edges: List[Tuple[str, str, float]]) -> Dict[Tuple[str, str], float]:
    """All-pairs shortest distances; unreachable -> math.inf."""
    if nodes is None:
        raise SearchError("nodes required")
    dist = {(u, v): (0 if u == v else math.inf) for u in nodes for v in nodes}
    for u, v, w in edges:
        if w < dist[(u, v)]:
            dist[(u, v)] = w
    for k in nodes:
        for i in nodes:
            dik = dist[(i, k)]
            for j in nodes:
                nd = dik + dist[(k, j)]
                if nd < dist[(i, j)]:
                    dist[(i, j)] = nd
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
    d = floyd_warshall(["a", "b", "c"], [("a", "b", 1), ("b", "c", 2)])
    assert d[("a", "c")] == 3
    assert d[("c", "a")] == __import__("math").inf
    assert d[("b", "b")] == 0
    assert stdlib_only()
    print("search-25.v1 OK")


if __name__ == "__main__":
    main()
