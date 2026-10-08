"""Group knapsack (multiple choice)

Items partitioned into groups; take at most one item per group.

What this IS: multiple-choice knapsack: at most one pick per group.

What this IS NOT:
* a plain 0/1 knapsack -- the group constraint is the point here.
* a solver that takes several items from one group.
"""

from __future__ import annotations

import ast
from typing import Dict, List, Set, Tuple

#: Module version.
KS_15_VERSION = "ks-15.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ks-15.v1"


def group_knapsack(groups, capacity):
    # groups: list of groups; each group is a list of (weight, value).
    # Take at most one item per group.
    if capacity < 0:
        raise ValueError("capacity must be >= 0")
    dp = [0] * (capacity + 1)
    for group in groups:
        prev = dp[:]
        for w, v in group:
            if w < 0:
                raise ValueError("weights must be >= 0")
            for c in range(w, capacity + 1):
                if prev[c - w] + v > dp[c]:
                    dp[c] = prev[c - w] + v
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
    assert group_knapsack([[(1, 1), (2, 3)], [(2, 2), (3, 4)]], 4) == 5
    assert group_knapsack([[(5, 10)]], 3) == 0
    assert group_knapsack([], 5) == 0
    assert group_knapsack([[(1, 2)], [(1, 3)]], 1) == 3
    assert stdlib_only()
    print("15-group OK")


if __name__ == "__main__":
    main()
