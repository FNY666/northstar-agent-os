"""Jump search, Simulated.

What this IS: O(sqrt n) block search on sorted data.

What this IS NOT: not optimal vs binary search; jumps need sorted input.
"""

from __future__ import annotations

import ast
import math
from typing import List

#: Module version.
SEARCH_03_VERSION = "search-03.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.search-03.v1"


class SearchError(Exception):
    """Fail-closed."""


def jump_search(items: List[int], target: int) -> int:
    """Return index of target in sorted items, or -1."""
    if items is None:
        raise SearchError("items required")
    n = len(items)
    if n == 0:
        return -1
    step = int(math.sqrt(n)) or 1
    prev = 0
    while prev < n and items[min(prev + step, n) - 1] < target:
        prev += step
    for i in range(prev, min(prev + step, n)):
        if items[i] == target:
            return i
        if items[i] > target:
            break
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
    assert jump_search([1, 3, 5, 7, 9, 11], 7) == 3
    assert jump_search([1, 3, 5, 7, 9, 11], 8) == -1
    assert jump_search([], 1) == -1
    assert stdlib_only()
    print("search-03.v1 OK")


if __name__ == "__main__":
    main()
