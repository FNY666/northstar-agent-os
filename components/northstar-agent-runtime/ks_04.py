"""Exact-fill knapsack (feasibility)

Decide whether some subset of weights sums to exactly the capacity.

What this IS: a feasibility check: can the capacity be filled exactly?

What this IS NOT:
* a value maximizer -- this only answers yes/no.
* a guarantee about which subset -- use ks_11 for recovery.
"""

from __future__ import annotations

import ast
from typing import Dict, List, Set, Tuple

#: Module version.
KS_04_VERSION = "ks-04.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ks-04.v1"


def can_fill_exactly(weights, capacity):
    # True iff some subset sums to exactly capacity.
    if capacity < 0:
        raise ValueError("capacity must be >= 0")
    reachable = {0}
    for w in weights:
        if w < 0:
            raise ValueError("weights must be >= 0")
        reachable |= {r + w for r in reachable if r + w <= capacity}
    return capacity in reachable

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
    assert can_fill_exactly([1, 3, 4], 7) is True
    assert can_fill_exactly([2, 4], 7) is False
    assert can_fill_exactly([], 0) is True
    assert can_fill_exactly([5], 3) is False
    assert stdlib_only()
    print("04-exact-fill OK")


if __name__ == "__main__":
    main()
