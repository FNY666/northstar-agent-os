"""Knapsack with at least m items

Max value using at least m items; -1 if impossible.

What this IS: cardinality-floor knapsack: value max with a minimum pick count.

What this IS NOT:
* an at-most-k solver -- this bounds the count from below.
* a solver that relaxes the floor when infeasible.
"""

from __future__ import annotations

import ast
from typing import Dict, List, Set, Tuple

#: Module version.
KS_42_VERSION = "ks-42.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ks-42.v1"


def knapsack_at_least_m(weights, values, capacity, m):
    # Max value using at least m items; -1 if impossible.
    if capacity < 0 or m < 0:
        raise ValueError("capacity and m must be >= 0")
    n = len(weights)
    neg = -10 ** 18
    dp = [[neg] * (capacity + 1) for _ in range(n + 1)]
    dp[0][0] = 0
    for w, v in zip(weights, values):
        for t in range(n, 0, -1):
            for c in range(capacity, w - 1, -1):
                if dp[t - 1][c - w] != neg:
                    cand = dp[t - 1][c - w] + v
                    if cand > dp[t][c]:
                        dp[t][c] = cand
    best = neg
    for t in range(m, n + 1):
        best = max(best, max(dp[t]))
    return -1 if best == neg else best

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
    assert knapsack_at_least_m([1, 2, 3], [6, 10, 12], 5, 2) == 22
    assert knapsack_at_least_m([1, 2, 3], [6, 10, 12], 5, 3) == -1
    assert knapsack_at_least_m([1, 2, 3], [6, 10, 12], 5, 0) == 22
    assert knapsack_at_least_m([], [], 5, 0) == 0
    assert stdlib_only()
    print("42-at-least-m OK")


if __name__ == "__main__":
    main()
