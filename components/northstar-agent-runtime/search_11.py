"""Lower/upper bound, Simulated.

What this IS: first index >= target (lower) and first index > target (upper).

What this IS NOT: needs sorted input; returns insertion points, not booleans.
"""

from __future__ import annotations

import ast
from typing import List

#: Module version.
SEARCH_11_VERSION = "search-11.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.search-11.v1"


class SearchError(Exception):
    """Fail-closed."""


def lower_bound(items: List[int], target: int) -> int:
    """First index with items[i] >= target."""
    if items is None:
        raise SearchError("items required")
    lo, hi = 0, len(items)
    while lo < hi:
        mid = (lo + hi) // 2
        if items[mid] < target:
            lo = mid + 1
        else:
            hi = mid
    return lo


def upper_bound(items: List[int], target: int) -> int:
    """First index with items[i] > target."""
    if items is None:
        raise SearchError("items required")
    lo, hi = 0, len(items)
    while lo < hi:
        mid = (lo + hi) // 2
        if items[mid] <= target:
            lo = mid + 1
        else:
            hi = mid
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
    assert lower_bound([1, 2, 2, 3], 2) == 1
    assert upper_bound([1, 2, 2, 3], 2) == 3
    assert lower_bound([], 5) == 0
    assert stdlib_only()
    print("search-11.v1 OK")


if __name__ == "__main__":
    main()
