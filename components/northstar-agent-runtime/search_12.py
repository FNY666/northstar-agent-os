"""Predicate binary search, Simulated.

What this IS: finds first index where a monotone predicate turns true.

What this IS NOT: requires monotonicity; garbage in, garbage out otherwise.
"""

from __future__ import annotations

import ast
from typing import Callable

#: Module version.
SEARCH_12_VERSION = "search-12.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.search-12.v1"


class SearchError(Exception):
    """Fail-closed."""


def first_true(pred: Callable[[int], bool], n: int) -> int:
    """Smallest i in [0, n) with pred(i) true; returns n if none."""
    if pred is None:
        raise SearchError("pred required")
    if n < 0:
        raise SearchError("n must be >= 0")
    lo, hi = 0, n
    while lo < hi:
        mid = (lo + hi) // 2
        if pred(mid):
            hi = mid
        else:
            lo = mid + 1
    return lo

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
    assert first_true(lambda i: i >= 5, 10) == 5
    assert first_true(lambda i: False, 10) == 10
    assert first_true(lambda i: True, 10) == 0
    assert stdlib_only()
    print("search-12.v1 OK")


if __name__ == "__main__":
    main()
