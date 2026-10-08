"""Exact-fill max-value knapsack

Max value among subsets filling capacity exactly; -1 if impossible.

What this IS: exact-fill optimization: best value under a hard equality.

What this IS NOT:
* a <= capacity solver -- equality is required here.
* a feasibility check -- use ks_04 for yes/no.
"""

from __future__ import annotations

import ast
from typing import Dict, List, Set, Tuple

#: Module version.
KS_41_VERSION = "ks-41.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ks-41.v1"


def knapsack_exact_fill_max(weights, values, capacity):
    # Max value among subsets filling capacity exactly; -1 if impossible.
    if capacity < 0:
        raise ValueError("capacity must be >= 0")
    neg = -10 ** 18
    dp = [neg] * (capacity + 1)
    dp[0] = 0
    for w, v in zip(weights, values):
        for c in range(capacity, w - 1, -1):
            if dp[c - w] != neg and dp[c - w] + v > dp[c]:
                dp[c] = dp[c - w] + v
    return -1 if dp[capacity] == neg else dp[capacity]

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
    assert knapsack_exact_fill_max([2, 3, 4], [3, 4, 5], 7) == 9
    assert knapsack_exact_fill_max([2, 3, 4], [3, 4, 5], 6) == 8
    assert knapsack_exact_fill_max([5], [9], 4) == -1
    assert knapsack_exact_fill_max([], [], 0) == 0
    assert stdlib_only()
    print("41-exact-max OK")


if __name__ == "__main__":
    main()
