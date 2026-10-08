"""Peak element search, Simulated.

What this IS: O(log n) binary search for any peak (a[i-1] <= a[i] >= a[i+1]).

What this IS NOT: does not find the global maximum, just a peak.
"""

from __future__ import annotations

import ast
from typing import List

#: Module version.
SEARCH_10_VERSION = "search-10.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.search-10.v1"


class SearchError(Exception):
    """Fail-closed."""


def peak_element(items: List[int]) -> int:
    """Return an index i that is a peak. Raises on empty input."""
    if not items:
        raise SearchError("items required")
    lo, hi = 0, len(items) - 1
    while lo < hi:
        mid = (lo + hi) // 2
        if items[mid] < items[mid + 1]:
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
    i = peak_element([1, 2, 1, 3, 5, 6, 4])
    assert peak_element([7]) == 0
    left_ok = i == 0 or [1, 2, 1, 3, 5, 6, 4][i - 1] <= [1, 2, 1, 3, 5, 6, 4][i]
    right_ok = i == 6 or [1, 2, 1, 3, 5, 6, 4][i + 1] <= [1, 2, 1, 3, 5, 6, 4][i]
    assert left_ok and right_ok
    assert stdlib_only()
    print("search-10.v1 OK")


if __name__ == "__main__":
    main()
