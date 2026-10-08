"""Fibonacci search, Simulated.

What this IS: division-free O(log n) search using Fibonacci numbers.

What this IS NOT: needs sorted input; more code than binary for same result.
"""

from __future__ import annotations

import ast
from typing import List

#: Module version.
SEARCH_07_VERSION = "search-07.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.search-07.v1"


class SearchError(Exception):
    """Fail-closed."""


def fibonacci_search(items: List[int], target: int) -> int:
    """Return index of target in sorted items, or -1."""
    if items is None:
        raise SearchError("items required")
    n = len(items)
    f2, f1 = 0, 1
    f = f1 + f2
    while f < n:
        f2, f1 = f1, f
        f = f1 + f2
    offset = -1
    while f > 1:
        i = min(offset + f2, n - 1)
        if items[i] < target:
            f, f1 = f1, f2
            f2 = f - f1
            offset = i
        elif items[i] > target:
            f, f1 = f2, f1 - f2
            f2 = f - f1
        else:
            return i
    if f1 and offset + 1 < n and items[offset + 1] == target:
        return offset + 1
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
    data = list(range(1, 11))
    assert fibonacci_search(data, 7) == 6
    assert fibonacci_search(data, 11) == -1
    assert fibonacci_search([], 1) == -1
    assert stdlib_only()
    print("search-07.v1 OK")


if __name__ == "__main__":
    main()
