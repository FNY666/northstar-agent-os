"""Knapsack with at most k items

0/1 knapsack limited to using at most k items.

What this IS: cardinality-constrained knapsack: value max with an item budget.

What this IS NOT:
* a plain 0/1 knapsack -- the item count is bounded here.
* an exact-k solver -- use ks_28 for exactly k.
"""

from __future__ import annotations

import ast
from typing import Dict, List, Set, Tuple

#: Module version.
KS_25_VERSION = "ks-25.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ks-25.v1"


def knapsack_at_most_k(weights, values, capacity, k):
    # 0/1 knapsack using at most k items.
    if capacity < 0 or k < 0:
        raise ValueError("capacity and k must be >= 0")
    dp = [[0] * (capacity + 1) for _ in range(k + 1)]
    for w, v in zip(weights, values):
        for t in range(k, 0, -1):
            for c in range(capacity, w - 1, -1):
                cand = dp[t - 1][c - w] + v
                if cand > dp[t][c]:
                    dp[t][c] = cand
    return max(dp[t][capacity] for t in range(k + 1))

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
    assert knapsack_at_most_k([1, 2, 3], [6, 10, 12], 5, 2) == 22
    assert knapsack_at_most_k([1, 2, 3], [6, 10, 12], 5, 1) == 12
    assert knapsack_at_most_k([1, 2, 3], [6, 10, 12], 5, 0) == 0
    assert knapsack_at_most_k([], [], 5, 3) == 0
    assert stdlib_only()
    print("25-at-most-k OK")


if __name__ == "__main__":
    main()
