"""Knapsack with conflicts

Pairs of items that cannot both be taken.

What this IS: 0/1 knapsack with pairwise conflict constraints, via subset search.

What this IS NOT:
* a plain 0/1 knapsack -- conflicts forbid co-selection here.
* a polynomial solver -- this is exponential in n.
"""

from __future__ import annotations

import ast
from typing import Dict, List, Set, Tuple

#: Module version.
KS_37_VERSION = "ks-37.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ks-37.v1"


def knapsack_conflicts(weights, values, capacity, conflicts):
    # conflicts: iterable of (i, j) pairs that cannot both be taken.
    if capacity < 0:
        raise ValueError("capacity must be >= 0")
    bad = set()
    for a, b in conflicts:
        bad.add((a, b))
        bad.add((b, a))
    n = len(weights)
    best = 0
    for mask in range(1 << n):
        chosen = [i for i in range(n) if (mask >> i) & 1]
        ok = True
        for x in range(len(chosen)):
            for y in range(x + 1, len(chosen)):
                if (chosen[x], chosen[y]) in bad:
                    ok = False
                    break
            if not ok:
                break
        if not ok:
            continue
        wsum = sum(weights[i] for i in chosen)
        if wsum <= capacity:
            vsum = sum(values[i] for i in chosen)
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
    assert knapsack_conflicts([2, 3, 4], [3, 4, 5], 6, {(0, 1)}) == 8
    assert knapsack_conflicts([2, 3], [3, 4], 5, set()) == 7
    assert knapsack_conflicts([2], [3], 2, set()) == 3
    assert knapsack_conflicts([5], [9], 4, set()) == 0
    assert stdlib_only()
    print("37-conflicts OK")


if __name__ == "__main__":
    main()
