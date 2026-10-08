"""Knapsack maximizing item count

Fit as many items as possible within the capacity.

What this IS: 0/1 knapsack maximizing count instead of value.

What this IS NOT:
* a value maximizer -- every item counts equally here.
* a solver that prefers heavy items.
"""

from __future__ import annotations

import ast
from typing import Dict, List, Set, Tuple

#: Module version.
KS_29_VERSION = "ks-29.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ks-29.v1"


def knapsack_max_count(weights, capacity):
    # Max number of items fitting in capacity.
    if capacity < 0:
        raise ValueError("capacity must be >= 0")
    neg = -10 ** 18
    dp = [neg] * (capacity + 1)
    dp[0] = 0
    for w in weights:
        if w < 0:
            raise ValueError("weights must be >= 0")
        for c in range(capacity, w - 1, -1):
            if dp[c - w] != neg and dp[c - w] + 1 > dp[c]:
                dp[c] = dp[c - w] + 1
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
    assert knapsack_max_count([1, 2, 3], 5) == 2
    assert knapsack_max_count([1, 1, 1], 2) == 2
    assert knapsack_max_count([5], 3) == 0
    assert knapsack_max_count([], 5) == 0
    assert stdlib_only()
    print("29-max-count OK")


if __name__ == "__main__":
    main()
