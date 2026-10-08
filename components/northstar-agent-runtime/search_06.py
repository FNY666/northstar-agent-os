"""Ternary search, Simulated.

What this IS: splits sorted range into thirds; O(log3 n) comparisons.

What this IS NOT: not faster than binary in practice; needs sorted input.
"""

from __future__ import annotations

import ast
from typing import List

#: Module version.
SEARCH_06_VERSION = "search-06.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.search-06.v1"


class SearchError(Exception):
    """Fail-closed."""


def ternary_search(items: List[int], target: int) -> int:
    """Return index of target in sorted items, or -1."""
    if items is None:
        raise SearchError("items required")
    lo, hi = 0, len(items) - 1
    while lo <= hi:
        third = (hi - lo) // 3
        m1, m2 = lo + third, hi - third
        if items[m1] == target:
            return m1
        if items[m2] == target:
            return m2
        if target < items[m1]:
            hi = m1 - 1
        elif target > items[m2]:
            lo = m2 + 1
        else:
            lo, hi = m1 + 1, m2 - 1
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
    assert ternary_search([1, 2, 3, 4, 5, 6, 7, 8, 9, 10], 7) == 6
    assert ternary_search([1, 2, 3, 4, 5], 9) == -1
    assert ternary_search([], 1) == -1
    assert stdlib_only()
    print("search-06.v1 OK")


if __name__ == "__main__":
    main()
