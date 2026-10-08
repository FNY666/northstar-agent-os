"""Branch and bound (mock), Simulated.

What this IS: mock 0/1 knapsack solver with fractional-knapsack bounds.

What this IS NOT: mock/simplified simulation; bound is problem-specific.
"""

from __future__ import annotations

import ast
from typing import List, Tuple

#: Module version.
SEARCH_42_VERSION = "search-42.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.search-42.v1"


class SearchError(Exception):
    """Fail-closed."""


def knapsack_branch_bound(items: List[Tuple[float, float]],
                          capacity: float) -> float:
    """Mock B&B: optimal 0/1 knapsack value."""
    if capacity < 0:
        raise SearchError("capacity must be >= 0")
    items = sorted(items, key=lambda x: x[0] / x[1] if x[1] else 0,
                   reverse=True)
    n = len(items)
    best = 0.0

    def bound(i: int, value: float, weight: float) -> float:
        if weight > capacity:
            return 0
        b, w = value, weight
        j = i
        while j < n and w + items[j][1] <= capacity:
            w += items[j][1]
            b += items[j][0]
            j += 1
        if j < n and items[j][1]:
            b += (capacity - w) * items[j][0] / items[j][1]
        return b

    def dfs(i: int, value: float, weight: float) -> None:
        nonlocal best
        if weight > capacity:
            return
        if value > best:
            best = value
        if i == n:
            return
        if bound(i, value, weight) <= best:
            return
        v, w = items[i]
        dfs(i + 1, value + v, weight + w)
        dfs(i + 1, value, weight)

    dfs(0, 0, 0)
    return best

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
    assert knapsack_branch_bound([(60, 10), (100, 20), (120, 30)], 50) == 220
    assert knapsack_branch_bound([], 50) == 0
    assert stdlib_only()
    print("search-42.v1 OK")


if __name__ == "__main__":
    main()
