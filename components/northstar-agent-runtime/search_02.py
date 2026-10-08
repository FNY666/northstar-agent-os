"""Binary search, Simulated.

What this IS: O(log n) search on sorted data.

What this IS NOT: not valid on unsorted data; sort first or use linear search.
"""

from __future__ import annotations

import ast
from typing import List

#: Module version.
SEARCH_02_VERSION = "search-02.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.search-02.v1"


class SearchError(Exception):
    """Fail-closed."""


def binary_search(items: List[int], target: int) -> int:
    """Return an index of target in sorted items, or -1."""
    if items is None:
        raise SearchError("items required")
    lo, hi = 0, len(items) - 1
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
    assert binary_search([1, 3, 5, 7, 9], 7) == 3
    assert binary_search([1, 3, 5, 7, 9], 4) == -1
    assert binary_search([], 1) == -1
    assert stdlib_only()
    print("search-02.v1 OK")


if __name__ == "__main__":
    main()
