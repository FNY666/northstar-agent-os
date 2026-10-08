"""Nested knapsack (group capacities)

Each group also has its own weight limit.

What this IS: knapsack with per-group weight caps on top of the global cap.

What this IS NOT:
* a plain 0/1 knapsack -- group budgets bind here too.
* a polynomial solver -- this is exponential in n.
"""

from __future__ import annotations

import ast
from typing import Dict, List, Set, Tuple

#: Module version.
KS_48_VERSION = "ks-48.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ks-48.v1"


def knapsack_nested(weights, values, groups, group_caps, capacity):
    # Each group g also limited to group_caps[g] total weight. Brute force.
    if capacity < 0:
        raise ValueError("capacity must be >= 0")
    n = len(weights)
    best = 0
    for mask in range(1 << n):
        wsum = 0
        vsum = 0
        gw = {}
        for i in range(n):
            if (mask >> i) & 1:
                wsum += weights[i]
                vsum += values[i]
                gw[groups[i]] = gw.get(groups[i], 0) + weights[i]
        if wsum > capacity:
            continue
        if any(gw[g] > group_caps[g] for g in gw):
            continue
        if vsum > best:
            best = vsum
    return best

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
    assert knapsack_nested([2, 2, 2], [3, 4, 5], [0, 0, 1], {0: 3, 1: 5}, 6) == 9
    assert knapsack_nested([2, 2], [3, 4], [0, 0], {0: 2}, 4) == 4
    assert knapsack_nested([], [], [], {}, 5) == 0
    assert knapsack_nested([1], [9], [0], {0: 0}, 5) == 0
    assert stdlib_only()
    print("48-nested OK")


if __name__ == "__main__":
    main()
