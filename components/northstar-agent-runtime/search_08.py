"""Sentinel linear search, Simulated.

What this IS: linear scan with a sentinel to skip the bounds check.

What this IS NOT: still O(n); only saves one comparison per step.
"""

from __future__ import annotations

import ast
from typing import List

#: Module version.
SEARCH_08_VERSION = "search-08.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.search-08.v1"


class SearchError(Exception):
    """Fail-closed."""


def sentinel_linear_search(items: List[int], target: int) -> int:
    """Return first index of target, or -1, using a sentinel."""
    if items is None:
        raise SearchError("items required")
    n = len(items)
    if n == 0:
        return -1
    work = list(items) + [target]
    i = 0
    while work[i] != target:
        i += 1
    return i if i < n else -1

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
    assert sentinel_linear_search([3, 1, 4, 1], 4) == 2
    assert sentinel_linear_search([3, 1, 4], 9) == -1
    assert sentinel_linear_search([], 1) == -1
    assert stdlib_only()
    print("search-08.v1 OK")


if __name__ == "__main__":
    main()
