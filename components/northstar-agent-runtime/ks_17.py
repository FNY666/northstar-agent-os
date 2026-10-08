"""Coin change (min coins)

Fewest coins making an amount; -1 if impossible.

What this IS: unbounded knapsack minimizing coin count for an exact amount.

What this IS NOT:
* a combination counter -- use ks_18 to count ways.
* a guarantee for non-canonical coin systems via greedy.
"""

from __future__ import annotations

import ast
from typing import Dict, List, Set, Tuple

#: Module version.
KS_17_VERSION = "ks-17.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ks-17.v1"


def coin_change(coins, amount):
    # Min coins to make amount; -1 if impossible.
    if amount < 0:
        raise ValueError("amount must be >= 0")
    inf = 10 ** 18
    dp = [inf] * (amount + 1)
    dp[0] = 0
    for a in range(1, amount + 1):
        for c in coins:
            if 0 < c <= a and dp[a - c] + 1 < dp[a]:
                dp[a] = dp[a - c] + 1
    return -1 if dp[amount] >= inf else dp[amount]

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
    assert coin_change([1, 2, 5], 11) == 3
    assert coin_change([2], 3) == -1
    assert coin_change([1], 0) == 0
    assert coin_change([1, 2, 5], 6) == 2
    assert stdlib_only()
    print("17-coin-change OK")


if __name__ == "__main__":
    main()
