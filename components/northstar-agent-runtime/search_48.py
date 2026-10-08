"""Union-find components, Simulated.

What this IS: connected components via disjoint-set union with path compression.

What this IS NOT: not for directed reachability; use DFS there.
"""

from __future__ import annotations

import ast
from typing import Any, Dict, List, Tuple

#: Module version.
SEARCH_48_VERSION = "search-48.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.search-48.v1"


class SearchError(Exception):
    """Fail-closed."""


class UnionFind:
    """Disjoint-set union with path compression."""

    def __init__(self) -> None:
        self.p: Dict[Any, Any] = {}

    def find(self, x: Any) -> Any:
        self.p.setdefault(x, x)
        while self.p[x] != x:
            self.p[x] = self.p[self.p[x]]
            x = self.p[x]
        return x

    def union(self, a: Any, b: Any) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.p[ra] = rb


def connected_components(nodes: List[Any],
                         edges: List[Tuple[Any, Any]]) -> List[List[Any]]:
    """Partition of nodes into connected components."""
    if nodes is None:
        raise SearchError("nodes required")
    uf = UnionFind()
    for n in nodes:
        uf.find(n)
    for a, b in edges:
        uf.union(a, b)
    comps: Dict[Any, List[Any]] = {}
    for n in nodes:
        comps.setdefault(uf.find(n), []).append(n)
    return list(comps.values())

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
    c = connected_components([1, 2, 3, 4], [(1, 2), (3, 4)])
    assert len(c) == 2
    assert len(connected_components([1, 2], [])) == 2
    assert stdlib_only()
    print("search-48.v1 OK")


if __name__ == "__main__":
    main()
