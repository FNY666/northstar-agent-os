"""Rotated binary search, Simulated.

What this IS: O(log n) search in a rotated sorted array.

What this IS NOT: needs distinct elements and one rotation point.
"""

from __future__ import annotations

import ast
from typing import List

#: Module version.
SEARCH_09_VERSION = "search-09.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.search-09.v1"


class SearchError(Exception):
    """Fail-closed."""


def rotated_binary_search(items: List[int], target: int) -> int:
    """Return index of target in rotated sorted items, or -1."""
    if items is None:
        raise SearchError("items required")
    lo, hi = 0, len(items) - 1
    while lo <= hi:
        mid = (lo + hi) // 2
        if items[mid] == target:
            return mid
        if items[lo] <= items[mid]:
            if items[lo] <= target < items[mid]:
                hi = mid - 1
            else:
                lo = mid + 1
        else:
            if items[mid] < target <= items[hi]:
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
    assert rotated_binary_search([4, 5, 6, 7, 0, 1, 2], 0) == 4
    assert rotated_binary_search([4, 5, 6, 7, 0, 1, 2], 3) == -1
    assert rotated_binary_search([1, 2, 3], 2) == 1
    assert stdlib_only()
    print("search-09.v1 OK")


if __name__ == "__main__":
    main()
