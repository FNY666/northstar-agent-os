"""Coin change II (count ways)

Count combinations making an amount; order does not matter.

What this IS: unbounded knapsack counting combinations for an exact amount.

What this IS NOT:
* a min-coins solver -- use ks_17 for fewest coins.
* an ordered counter -- use ks_19 when order matters.
"""

from __future__ import annotations

import ast
from typing import Dict, List, Set, Tuple

#: Module version.
KS_18_VERSION = "ks-18.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ks-18.v1"


def change_ways(coins, amount):
    # Number of combinations making amount (order irrelevant).
    if amount < 0:
        return 0
    dp = [0] * (amount + 1)
    dp[0] = 1
    for c in coins:
        if c <= 0:
            raise ValueError("coins must be > 0")
        for a in range(c, amount + 1):
            dp[a] += dp[a - c]
    return dp[amount]

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
    assert change_ways([1, 2, 5], 5) == 4
    assert change_ways([2], 3) == 0
    assert change_ways([1, 2, 5], 0) == 1
    assert change_ways([10], 10) == 1
    assert stdlib_only()
    print("18-change-ways OK")


if __name__ == "__main__":
    main()
