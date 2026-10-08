"""Topological sort, Simulated.

What this IS: Kahn's algorithm; linear order respecting dependencies.

What this IS NOT: fails on cycles; order is not unique.
"""

from __future__ import annotations

import ast
from collections import deque
from typing import Dict, List

#: Module version.
SEARCH_47_VERSION = "search-47.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.search-47.v1"


class SearchError(Exception):
    """Fail-closed."""


def topological_sort(graph: Dict[str, List[str]]) -> List[str]:
    """Topological order; raises SearchError on cycle."""
    if graph is None:
        raise SearchError("graph required")
    indeg = {n: 0 for n in graph}
    for u in graph:
        for v in graph[u]:
            indeg[v] = indeg.get(v, 0) + 1
    q = deque([n for n, d in indeg.items() if d == 0])
    order = []
    while q:
        u = q.popleft()
        order.append(u)
        for v in graph.get(u, []):
            indeg[v] -= 1
            if indeg[v] == 0:
                q.append(v)
    if len(order) != len(indeg):
        raise SearchError("cycle detected")
    return order

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
    o = topological_sort(g)
    assert o.index("a") < o.index("b") < o.index("d")
    assert o.index("a") < o.index("c") < o.index("d")
    assert stdlib_only()
    print("search-47.v1 OK")


if __name__ == "__main__":
    main()
