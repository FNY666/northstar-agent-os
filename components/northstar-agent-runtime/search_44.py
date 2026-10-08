"""Subset-sum backtracking, Simulated.

What this IS: finds a subset summing to target (non-negative numbers).

What this IS NOT: exponential worst case; not for negative numbers.
"""

from __future__ import annotations

import ast
from typing import List, Optional

#: Module version.
SEARCH_44_VERSION = "search-44.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.search-44.v1"


class SearchError(Exception):
    """Fail-closed."""


def subset_sum(nums: List[int], target: int) -> Optional[List[int]]:
    """A subset summing to target, or None."""
    if nums is None:
        raise SearchError("nums required")

    def bt(i: int, cur: int, path: List[int]) -> bool:
        if cur == target:
            return True
        if i == len(nums) or cur > target:
            return False
        path.append(nums[i])
        if bt(i + 1, cur + nums[i], path):
            return True
        path.pop()
        return bt(i + 1, cur, path)

    path: List[int] = []
    return path if bt(0, 0, path) else None

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
    r = subset_sum([3, 34, 4, 12, 5, 2], 9)
    assert r is not None and sum(r) == 9
    assert subset_sum([3, 34, 4, 12, 5, 2], 100) is None
    assert subset_sum([], 0) == []
    assert stdlib_only()
    print("search-44.v1 OK")


if __name__ == "__main__":
    main()
