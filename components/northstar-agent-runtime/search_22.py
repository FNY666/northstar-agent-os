"""Depth-limited search, Simulated.

What this IS: DFS that never goes deeper than the limit.

What this IS NOT: incomplete beyond the limit; use IDDFS to fix that.
"""

from __future__ import annotations

import ast
from typing import Dict, List, Optional

#: Module version.
SEARCH_22_VERSION = "search-22.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.search-22.v1"


class SearchError(Exception):
    """Fail-closed."""


def depth_limited_search(graph: Dict[str, List[str]], start: str,
                         goal: str, limit: int) -> Optional[List[str]]:
    """Path within limit edges, or None."""
    if graph is None:
        raise SearchError("graph required")
    if limit < 0:
        raise SearchError("limit must be >= 0")

    def dls(node: str, depth: int, seen: set) -> Optional[List[str]]:
        if node == goal:
            return [node]
        if depth == 0:
            return None
        seen.add(node)
        for nb in graph.get(node, []):
            if nb in seen:
                continue
            res = dls(nb, depth - 1, seen)
            if res:
                return [node] + res
        seen.discard(node)
        return None

    return dls(start, limit, set())

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
    chain = {"a": ["b"], "b": ["c"], "c": []}
    assert depth_limited_search(chain, "a", "c", 2) == ["a", "b", "c"]
    assert depth_limited_search(chain, "a", "c", 1) is None
    assert stdlib_only()
    print("search-22.v1 OK")


if __name__ == "__main__":
    main()
