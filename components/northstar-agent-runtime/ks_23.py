"""Value-capped knapsack

0/1 knapsack where total value is capped at a ceiling.

What this IS: 0/1 knapsack with diminishing returns past a value cap.

What this IS NOT:
* a plain 0/1 knapsack -- the cap models saturation.
* a model of per-item caps -- the cap applies to the total.
"""

from __future__ import annotations

import ast
from typing import Dict, List, Set, Tuple

#: Module version.
KS_23_VERSION = "ks-23.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ks-23.v1"


def knapsack_value_capped(weights, values, capacity, value_cap):
    # 0/1 knapsack where total value is capped at value_cap.
    if capacity < 0 or value_cap < 0:
        raise ValueError("capacity and value_cap must be >= 0")
    dp = [0] * (capacity + 1)
    for w, v in zip(weights, values):
        for c in range(capacity, w - 1, -1):
            cand = dp[c - w] + v
            if cand > value_cap:
                cand = value_cap
            if cand > dp[c]:
                dp[c] = cand
    return dp[capacity]

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
    assert knapsack_value_capped([5, 5], [10, 10], 10, 15) == 15
    assert knapsack_value_capped([5, 5], [10, 10], 10, 100) == 20
    assert knapsack_value_capped([5], [10], 3, 100) == 0
    assert knapsack_value_capped([], [], 5, 10) == 0
    assert stdlib_only()
    print("23-value-cap OK")


if __name__ == "__main__":
    main()
