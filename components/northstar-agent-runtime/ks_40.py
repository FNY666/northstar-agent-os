"""Knapsack with class bonuses

Bonus value for taking at least one item from a class.

What this IS: 0/1 knapsack with set bonuses for class coverage.

What this IS NOT:
* a plain 0/1 knapsack -- bonuses reward diversity here.
* a polynomial solver -- this is exponential in n.
"""

from __future__ import annotations

import ast
from typing import Dict, List, Set, Tuple

#: Module version.
KS_40_VERSION = "ks-40.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ks-40.v1"


def knapsack_class_bonus(weights, values, capacity, classes, bonuses):
    # bonuses[cid]: extra value if >=1 item of class cid taken.
    if capacity < 0:
        raise ValueError("capacity must be >= 0")
    n = len(weights)
    best = 0
    for mask in range(1 << n):
        wsum = 0
        vsum = 0
        seen = set()
        for i in range(n):
            if (mask >> i) & 1:
                wsum += weights[i]
                vsum += values[i]
                seen.add(classes[i])
        if wsum > capacity:
            continue
        vsum += sum(bonuses[c] for c in seen)
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
    assert knapsack_class_bonus([2, 2], [3, 3], 3, [0, 1], {0: 5, 1: 5}) == 8
    assert knapsack_class_bonus([2, 2], [3, 3], 4, [0, 0], {0: 5}) == 11
    assert knapsack_class_bonus([], [], 5, [], {}) == 0
    assert knapsack_class_bonus([5], [3], 3, [0], {0: 5}) == 0
    assert stdlib_only()
    print("40-class-bonus OK")


if __name__ == "__main__":
    main()
