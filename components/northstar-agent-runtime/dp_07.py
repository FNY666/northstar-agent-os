"""dp-07: 0/1 knapsack.

Max value with capacity limit, each item used at most once. Iterate capacities backwards so items are not reused.

Time complexity: O(n * capacity) time
Space complexity: O(capacity) space
"""

import ast
import sys
from typing import List

DP_07_VERSION = "dp-07.v1"


def knapsack(weights: List[int], values: List[int], capacity: int) -> int:
    """Return the maximum value fitting in capacity (each item at most once)."""
    if len(weights) != len(values):
        raise ValueError("weights and values must have equal length")
    if capacity < 0:
        raise ValueError("capacity must be non-negative")
    dp = [0] * (capacity + 1)
    for w, v in zip(weights, values):
        for c in range(capacity, w - 1, -1):
            dp[c] = max(dp[c], dp[c - w] + v)
    return dp[capacity]


def stdlib_only() -> bool:
    """Parse this file with ``ast`` and assert every import is a used stdlib module."""
    with open(__file__, encoding="utf-8") as f:
        source = f.read()
    tree = ast.parse(source)
    imported = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imported[alias.asname or alias.name.split(".")[0]] = alias.name.split(".")[0]
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                imported[alias.asname or alias.name] = (node.module or "").split(".")[0]
    used = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            used.add(node.id)
    for alias, top in imported.items():
        assert top in sys.stdlib_module_names, "non-stdlib import: %s" % top
        assert alias in used, "imported but unused: %s" % alias
    return True


def main() -> None:
    assert knapsack([1, 2, 3], [6, 10, 12], 5) == 22
    assert knapsack([2, 3, 4], [3, 4, 5], 5) == 7
    assert knapsack([1, 2, 3], [6, 10, 12], 0) == 0
    assert knapsack([], [], 10) == 0
    try:
        knapsack([1], [1, 2], 5)
        raise AssertionError("expected ValueError")
    except ValueError:
        pass
    assert stdlib_only()
    print("dp-07 OK")


if __name__ == "__main__":
    main()
