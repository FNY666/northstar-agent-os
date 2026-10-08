"""Interpolation search, Simulated.

What this IS: O(log log n) on uniformly distributed sorted data.

What this IS NOT: degrades on skewed data; needs numeric sorted input.
"""

from __future__ import annotations

import ast
from typing import List

#: Module version.
SEARCH_04_VERSION = "search-04.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.search-04.v1"


class SearchError(Exception):
    """Fail-closed."""


def interpolation_search(items: List[int], target: int) -> int:
    """Return index of target in sorted items, or -1."""
    if items is None:
        raise SearchError("items required")
    lo, hi = 0, len(items) - 1
    while lo <= hi and items[lo] <= target <= items[hi]:
        if items[hi] == items[lo]:
            return lo if items[lo] == target else -1
        pos = lo + (target - items[lo]) * (hi - lo) // (items[hi] - items[lo])
        if items[pos] == target:
            return pos
        if items[pos] < target:
            lo = pos + 1
        else:
            hi = pos - 1
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
    data = list(range(0, 1000, 2))
    assert interpolation_search(data, 500) == 250
    assert interpolation_search(data, 501) == -1
    assert interpolation_search([], 1) == -1
    assert stdlib_only()
    print("search-04.v1 OK")


if __name__ == "__main__":
    main()
