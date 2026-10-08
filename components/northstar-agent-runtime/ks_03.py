"""Unbounded knapsack

Each item may be reused an unlimited number of times.

What this IS: the unbounded knapsack: unlimited copies of every item.

What this IS NOT:
* a 0/1 knapsack -- reuse is allowed here.
* a coin-change counter -- this maximizes value.
"""

from __future__ import annotations

import ast
from typing import Dict, List, Set, Tuple

#: Module version.
KS_03_VERSION = "ks-03.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ks-03.v1"


def unbounded_knapsack(weights, values, capacity):
    # Items reusable unlimited times. O(n*C).
    if capacity < 0:
        raise ValueError("capacity must be >= 0")
    dp = [0] * (capacity + 1)
    for c in range(1, capacity + 1):
        for w, v in zip(weights, values):
            if 0 < w <= c and dp[c - w] + v > dp[c]:
                dp[c] = dp[c - w] + v
    return dp[capacity]

def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "pathlib", "typing"}
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
    assert unbounded_knapsack([1, 3, 4], [10, 40, 50], 6) == 80
    assert unbounded_knapsack([2], [3], 5) == 6
    assert unbounded_knapsack([], [], 5) == 0
    assert unbounded_knapsack([3], [5], 2) == 0
    assert stdlib_only()
    print("03-unbounded OK")


if __name__ == "__main__":
    main()
