"""0/1 knapsack (classic)

The textbook 0/1 knapsack: each item taken at most once, maximize value.

What this IS: the classic dynamic-programming 0/1 knapsack, O(n*C) time and O(C) space.

What this IS NOT:
* a fractional knapsack -- items are indivisible here.
* an unbounded knapsack -- each item may be used only once.
"""

from __future__ import annotations

import ast
from typing import Dict, List, Set, Tuple

#: Module version.
KS_01_VERSION = "ks-01.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ks-01.v1"


def knapsack_01(weights, values, capacity):
    # 0/1 knapsack: each item taken at most once. O(n*C) time, O(C) space.
    if capacity < 0:
        raise ValueError("capacity must be >= 0")
    dp = [0] * (capacity + 1)
    for w, v in zip(weights, values):
        if w < 0 or v < 0:
            raise ValueError("weights and values must be >= 0")
        for c in range(capacity, w - 1, -1):
            if dp[c - w] + v > dp[c]:
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
    assert knapsack_01([1, 3, 4, 5], [1, 4, 5, 7], 7) == 9
    assert knapsack_01([], [], 10) == 0
    assert knapsack_01([5], [10], 0) == 0
    assert knapsack_01([5], [10], 4) == 0
    assert knapsack_01([2, 2], [3, 4], 3) == 4
    assert stdlib_only()
    print("01-basic OK")


if __name__ == "__main__":
    main()
