"""dp-08: Unbounded knapsack.

Max value with capacity limit, each item usable unlimited times. Iterate capacities forwards so items can be reused.

Time complexity: O(n * capacity) time
Space complexity: O(capacity) space
"""

import ast
import sys
from typing import List

DP_08_VERSION = "dp-08.v1"


def unbounded_knapsack(weights: List[int], values: List[int], capacity: int) -> int:
    """Return the maximum value fitting in capacity (unlimited reuse of items)."""
    if len(weights) != len(values):
        raise ValueError("weights and values must have equal length")
    if capacity < 0:
        raise ValueError("capacity must be non-negative")
    dp = [0] * (capacity + 1)
    for c in range(1, capacity + 1):
        for w, v in zip(weights, values):
            if w <= c:
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
    assert unbounded_knapsack([1, 2, 3], [1, 5, 8], 4) == 10
    assert unbounded_knapsack([2, 3], [3, 5], 7) == 11
    assert unbounded_knapsack([2], [3], 1) == 0
    assert unbounded_knapsack([1], [7], 5) == 35
    try:
        unbounded_knapsack([1], [1, 2], 3)
        raise AssertionError("expected ValueError")
    except ValueError:
        pass
    assert stdlib_only()
    print("dp-08 OK")


if __name__ == "__main__":
    main()
