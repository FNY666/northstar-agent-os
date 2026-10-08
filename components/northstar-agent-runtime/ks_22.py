"""Rod cutting

Cut a rod of length n to maximize revenue from piece prices.

What this IS: unbounded knapsack: price of length i is an item of weight i.

What this IS NOT:
* a cutting planner -- this only returns max revenue.
* valid when prices can be negative.
"""

from __future__ import annotations

import ast
from typing import Dict, List, Set, Tuple

#: Module version.
KS_22_VERSION = "ks-22.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ks-22.v1"


def rod_cutting(prices, n):
    # prices[i] = price of length i+1; max revenue for length n.
    if n < 0:
        raise ValueError("n must be >= 0")
    dp = [0] * (n + 1)
    for i in range(1, n + 1):
        for j in range(1, min(i, len(prices)) + 1):
            cand = prices[j - 1] + dp[i - j]
            if cand > dp[i]:
                dp[i] = cand
    return dp[n]

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
    assert rod_cutting([1, 5, 8, 9, 10, 17, 17, 20], 8) == 22
    assert rod_cutting([3, 5], 2) == 6
    assert rod_cutting([1, 5, 8], 0) == 0
    assert rod_cutting([2], 3) == 6
    assert stdlib_only()
    print("22-rod-cutting OK")


if __name__ == "__main__":
    main()
