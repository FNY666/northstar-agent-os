"""Knapsack with deadlines

Schedule a subset so each job completes before its deadline.

What this IS: knapsack with scheduling deadlines: completion time must respect each deadline.

What this IS NOT:
* a plain knapsack -- time ordering constrains feasibility here.
* a preemptive scheduler -- jobs run to completion.
"""

from __future__ import annotations

import ast
from typing import Dict, List, Set, Tuple

#: Module version.
KS_43_VERSION = "ks-43.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ks-43.v1"


def knapsack_deadlines(weights, values, deadlines, capacity):
    # Schedule subset: order by deadline, completion time <= each deadline.
    if capacity < 0:
        raise ValueError("capacity must be >= 0")
    items = sorted(zip(weights, values, deadlines), key=lambda x: x[2])
    neg = -10 ** 18
    dp = [neg] * (capacity + 1)
    dp[0] = 0
    for w, v, d in items:
        for t in range(min(d, capacity), w - 1, -1):
            if dp[t - w] != neg:
                cand = dp[t - w] + v
                if cand > dp[t]:
                    dp[t] = cand
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
    assert knapsack_deadlines([2, 2], [5, 6], [2, 3], 4) == 6
    assert knapsack_deadlines([3], [7], [2], 5) == 0
    assert knapsack_deadlines([], [], [], 5) == 0
    assert knapsack_deadlines([1, 1], [2, 3], [5, 5], 2) == 5
    assert stdlib_only()
    print("43-deadlines OK")


if __name__ == "__main__":
    main()
