"""2D knapsack (weight + volume)

Two resource constraints; maximize value.

What this IS: bi-dimensional 0/1 knapsack over weight and volume.

What this IS NOT:
* a single-constraint knapsack -- two resources bind here.
* a solver for three or more dimensions.
"""

from __future__ import annotations

import ast
from typing import Dict, List, Set, Tuple

#: Module version.
KS_26_VERSION = "ks-26.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ks-26.v1"


def knapsack_2d(weights1, weights2, values, cap1, cap2):
    # Two resource constraints; maximize value.
    if cap1 < 0 or cap2 < 0:
        raise ValueError("capacities must be >= 0")
    dp = [[0] * (cap2 + 1) for _ in range(cap1 + 1)]
    for a, b, v in zip(weights1, weights2, values):
        for c1 in range(cap1, a - 1, -1):
            for c2 in range(cap2, b - 1, -1):
                cand = dp[c1 - a][c2 - b] + v
                if cand > dp[c1][c2]:
                    dp[c1][c2] = cand
    return dp[cap1][cap2]

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
    assert knapsack_2d([1, 2], [2, 1], [3, 4], 2, 2) == 4
    assert knapsack_2d([1], [1], [5], 0, 0) == 0
    assert knapsack_2d([1, 1], [1, 1], [3, 4], 2, 2) == 7
    assert knapsack_2d([], [], [], 3, 3) == 0
    assert stdlib_only()
    print("26-2d OK")


if __name__ == "__main__":
    main()
