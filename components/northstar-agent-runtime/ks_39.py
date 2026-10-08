"""Knapsack with max-fill tiebreak

Max value; ties broken by using more weight. Returns (value, weight).

What this IS: 0/1 knapsack whose optimum is the (value, weight) lexicographic max.

What this IS NOT:
* a value-only solver -- this also reports weight used.
* a solver that prefers lighter optima.
"""

from __future__ import annotations

import ast
from typing import Dict, List, Set, Tuple

#: Module version.
KS_39_VERSION = "ks-39.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ks-39.v1"


def knapsack_tiebreak_fill(weights, values, capacity):
    # Max value; ties broken by max weight used. Returns (value, weight).
    if capacity < 0:
        raise ValueError("capacity must be >= 0")
    dp = [(-1, -1)] * (capacity + 1)
    dp[0] = (0, 0)
    for w, v in zip(weights, values):
        for c in range(capacity, w - 1, -1):
            if dp[c - w][0] >= 0:
                cand = (dp[c - w][0] + v, c)
                if cand > dp[c]:
                    dp[c] = cand
    return max(dp)

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
    assert knapsack_tiebreak_fill([3, 4], [5, 5], 7) == (10, 7)
    assert knapsack_tiebreak_fill([3, 5], [5, 5], 7) == (5, 5)
    assert knapsack_tiebreak_fill([], [], 5) == (0, 0)
    assert knapsack_tiebreak_fill([8], [9], 5) == (0, 0)
    assert stdlib_only()
    print("39-tiebreak OK")


if __name__ == "__main__":
    main()
