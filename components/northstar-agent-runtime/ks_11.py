"""0/1 knapsack with item recovery

Maximize value and report which item indices were chosen.

What this IS: 0/1 knapsack with backtracking: returns (value, chosen indices).

What this IS NOT:
* a value-only solver -- use ks_01 when indices are unneeded.
* memory-light -- the 2D table costs O(n*C).
"""

from __future__ import annotations

import ast
from typing import Dict, List, Set, Tuple

#: Module version.
KS_11_VERSION = "ks-11.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ks-11.v1"


def knapsack_with_items(weights, values, capacity):
    # Returns (max_value, sorted list of chosen indices).
    if capacity < 0:
        raise ValueError("capacity must be >= 0")
    n = len(weights)
    dp = [[0] * (capacity + 1) for _ in range(n + 1)]
    for i in range(1, n + 1):
        w, v = weights[i - 1], values[i - 1]
        for c in range(capacity + 1):
            dp[i][c] = dp[i - 1][c]
            if w <= c and dp[i - 1][c - w] + v > dp[i][c]:
                dp[i][c] = dp[i - 1][c - w] + v
    chosen = []
    c = capacity
    for i in range(n, 0, -1):
        if dp[i][c] != dp[i - 1][c]:
            chosen.append(i - 1)
            c -= weights[i - 1]
    return dp[n][capacity], sorted(chosen)

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
    assert knapsack_with_items([1, 3, 4, 5], [1, 4, 5, 7], 7) == (9, [1, 2])
    assert knapsack_with_items([], [], 5) == (0, [])
    assert knapsack_with_items([5], [10], 3) == (0, [])
    assert knapsack_with_items([2], [7], 2) == (7, [0])
    assert stdlib_only()
    print("11-recovery OK")


if __name__ == "__main__":
    main()
