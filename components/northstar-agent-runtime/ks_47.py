"""Knapsack with setup costs

Using any item of a group adds a fixed setup weight.

What this IS: knapsack with group setup costs, via subset search.

What this IS NOT:
* a plain 0/1 knapsack -- setups penalize touching a group.
* a polynomial solver -- this is exponential in n.
"""

from __future__ import annotations

import ast
from typing import Dict, List, Set, Tuple

#: Module version.
KS_47_VERSION = "ks-47.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ks-47.v1"


def knapsack_setup(weights, values, groups, setups, capacity):
    # Using any item of group g adds setups[g] weight. Brute force.
    if capacity < 0:
        raise ValueError("capacity must be >= 0")
    n = len(weights)
    best = 0
    for mask in range(1 << n):
        wsum = 0
        vsum = 0
        used = set()
        for i in range(n):
            if (mask >> i) & 1:
                wsum += weights[i]
                vsum += values[i]
                used.add(groups[i])
        wsum += sum(setups[g] for g in used)
        if wsum <= capacity and vsum > best:
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
    assert knapsack_setup([2, 2], [5, 5], [0, 0], {0: 3}, 7) == 10
    assert knapsack_setup([2, 2], [5, 5], [0, 0], {0: 3}, 6) == 5
    assert knapsack_setup([], [], [], {}, 5) == 0
    assert knapsack_setup([4], [9], [0], {0: 2}, 5) == 0
    assert stdlib_only()
    print("47-setup-cost OK")


if __name__ == "__main__":
    main()
