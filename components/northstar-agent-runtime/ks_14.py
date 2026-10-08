"""Two knapsacks

Each item goes to sack 1, sack 2, or neither; maximize total value.

What this IS: the two-knapsack assignment over a 2D DP table.

What this IS NOT:
* two independent knapsacks -- items are shared here.
* a polynomial solver for three or more sacks.
"""

from __future__ import annotations

import ast
from typing import Dict, List, Set, Tuple

#: Module version.
KS_14_VERSION = "ks-14.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ks-14.v1"


def two_knapsacks(weights, values, cap1, cap2):
    # Each item goes to sack 1, sack 2, or neither.
    if cap1 < 0 or cap2 < 0:
        raise ValueError("capacities must be >= 0")
    dp = [[0] * (cap2 + 1) for _ in range(cap1 + 1)]
    for w, v in zip(weights, values):
        prev = [row[:] for row in dp]
        for c1 in range(cap1 + 1):
            for c2 in range(cap2 + 1):
                best = prev[c1][c2]
                if w <= c1 and prev[c1 - w][c2] + v > best:
                    best = prev[c1 - w][c2] + v
                if w <= c2 and prev[c1][c2 - w] + v > best:
                    best = prev[c1][c2 - w] + v
                dp[c1][c2] = best
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
    assert two_knapsacks([2, 3], [4, 5], 2, 3) == 9
    assert two_knapsacks([5], [10], 2, 3) == 0
    assert two_knapsacks([2], [4], 2, 2) == 4
    assert two_knapsacks([], [], 3, 3) == 0
    assert stdlib_only()
    print("14-two-sacks OK")


if __name__ == "__main__":
    main()
