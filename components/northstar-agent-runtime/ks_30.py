"""Max-fill knapsack (closest to full)

Maximize total weight without exceeding capacity.

What this IS: subset-sum optimization: pack the knapsack as full as possible.

What this IS NOT:
* a value maximizer -- weight itself is the objective.
* a solver that must fill the capacity exactly.
"""

from __future__ import annotations

import ast
from typing import Dict, List, Set, Tuple

#: Module version.
KS_30_VERSION = "ks-30.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ks-30.v1"


def knapsack_max_fill(weights, capacity):
    # Max total weight <= capacity (subset closest to full).
    if capacity < 0:
        raise ValueError("capacity must be >= 0")
    reachable = {0}
    for w in weights:
        if w < 0:
            raise ValueError("weights must be >= 0")
        reachable |= {r + w for r in reachable if r + w <= capacity}
    return max(reachable)

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
    assert knapsack_max_fill([3, 4, 5], 7) == 7
    assert knapsack_max_fill([5, 6], 4) == 0
    assert knapsack_max_fill([], 5) == 0
    assert knapsack_max_fill([2, 2, 2], 5) == 4
    assert stdlib_only()
    print("30-max-fill OK")


if __name__ == "__main__":
    main()
