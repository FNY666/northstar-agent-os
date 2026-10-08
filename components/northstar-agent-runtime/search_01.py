"""Linear search, Simulated.

What this IS: O(n) scan returning the first index of the target.

What this IS NOT: not efficient on large sorted data; use binary search.
"""

from __future__ import annotations

import ast
from typing import List

#: Module version.
SEARCH_01_VERSION = "search-01.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.search-01.v1"


class SearchError(Exception):
    """Fail-closed."""


def linear_search(items: List[int], target: int) -> int:
    """Return first index of target, or -1."""
    if items is None:
        raise SearchError("items required")
    for i, v in enumerate(items):
        if v == target:
            return i
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
    assert linear_search([3, 1, 4, 1], 1) == 1
    assert linear_search([3, 1, 4], 9) == -1
    assert linear_search([], 1) == -1
    assert stdlib_only()
    print("search-01.v1 OK")


if __name__ == "__main__":
    main()
