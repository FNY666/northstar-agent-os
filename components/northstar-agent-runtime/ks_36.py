"""Chain-precedence knapsack

Items form a chain; taking item i requires all of 0..i-1.

What this IS: knapsack on a precedence chain: feasible sets are exactly prefixes.

What this IS NOT:
* a free-choice knapsack -- order is forced here.
* a solver for branching prerequisites -- use ks_16 for trees.
"""

from __future__ import annotations

import ast
from typing import Dict, List, Set, Tuple

#: Module version.
KS_36_VERSION = "ks-36.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ks-36.v1"


def knapsack_chain(weights, values, capacity):
    # Items form a chain; taking item i requires all of 0..i-1.
    # Feasible sets are exactly the prefixes.
    if capacity < 0:
        raise ValueError("capacity must be >= 0")
    best = 0
    wsum = 0
    vsum = 0
    for w, v in zip(weights, values):
        wsum += w
        vsum += v
        if wsum > capacity:
            break
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
    assert knapsack_chain([2, 3, 4], [3, 4, 5], 6) == 7
    assert knapsack_chain([2, 3, 4], [3, 4, 5], 1) == 0
    assert knapsack_chain([], [], 5) == 0
    assert knapsack_chain([1, 1], [5, 6], 2) == 11
    assert stdlib_only()
    print("36-chain OK")


if __name__ == "__main__":
    main()
