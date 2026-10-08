"""Exponential search, Simulated.

What this IS: finds range by doubling then binary-searches; good for unbounded lists.

What this IS NOT: needs sorted input; not for unsorted data.
"""

from __future__ import annotations

import ast
from typing import List

#: Module version.
SEARCH_05_VERSION = "search-05.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.search-05.v1"


class SearchError(Exception):
    """Fail-closed."""


def exponential_search(items: List[int], target: int) -> int:
    """Return index of target in sorted items, or -1."""
    if items is None:
        raise SearchError("items required")
    n = len(items)
    if n == 0:
        return -1
    if items[0] == target:
        return 0
    bound = 1
    while bound < n and items[bound] < target:
        bound *= 2
    lo, hi = bound // 2, min(bound, n - 1)
    while lo <= hi:
        mid = (lo + hi) // 2
        if items[mid] == target:
            return mid
        if items[mid] < target:
            lo = mid + 1
        else:
            hi = mid - 1
    return -1

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
    data = list(range(1, 21))
    assert exponential_search(data, 15) == 14
    assert exponential_search(data, 21) == -1
    assert exponential_search([], 1) == -1
    assert stdlib_only()
    print("search-05.v1 OK")


if __name__ == "__main__":
    main()
