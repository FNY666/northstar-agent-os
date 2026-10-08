"""Minimax (mock), Simulated.

What this IS: mock game-tree solver; max/min over explicit trees.

What this IS NOT: mock/simplified simulation; trees are explicit, not generated.
"""

from __future__ import annotations

import ast
from typing import Any, Callable, List

#: Module version.
SEARCH_40_VERSION = "search-40.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.search-40.v1"


class SearchError(Exception):
    """Fail-closed."""


def minimax(node: Any, depth: int, maximizing: bool,
            children_fn: Callable[[Any], List[Any]],
            value_fn: Callable[[Any], float]) -> float:
    """Mock minimax value of node at given depth."""
    if children_fn is None or value_fn is None:
        raise SearchError("args required")
    kids = children_fn(node)
    if depth == 0 or not kids:
        return value_fn(node)
    if maximizing:
        return max(minimax(c, depth - 1, False, children_fn, value_fn)
                   for c in kids)
    return min(minimax(c, depth - 1, True, children_fn, value_fn)
               for c in kids)

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
    kids = {"r": ["a", "b"], "a": ["a1", "a2"], "b": ["b1", "b2"]}
    vals = {"a1": 3, "a2": 5, "b1": 2, "b2": 9}
    assert minimax("r", 2, True, kids.get, vals.__getitem__) == 3
    assert stdlib_only()
    print("search-40.v1 OK")


if __name__ == "__main__":
    main()
