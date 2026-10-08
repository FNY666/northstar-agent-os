"""Knapsack with mandatory items

Some items must be taken; -1 if they exceed capacity.

What this IS: 0/1 knapsack with forced picks: mandatory weight is pre-committed.

What this IS NOT:
* a free-choice knapsack -- some picks are forced here.
* a solver that drops mandatory items when tight -- it returns -1.
"""

from __future__ import annotations

import ast
from typing import Dict, List, Set, Tuple

#: Module version.
KS_38_VERSION = "ks-38.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ks-38.v1"


def knapsack_mandatory(weights, values, capacity, mandatory):
    # mandatory: indices that must be taken; -1 if they exceed capacity.
    if capacity < 0:
        raise ValueError("capacity must be >= 0")
    must = set(mandatory)
    wsum = sum(weights[i] for i in must)
    vsum = sum(values[i] for i in must)
    if wsum > capacity:
        return -1
    rest_w = [weights[i] for i in range(len(weights)) if i not in must]
    rest_v = [values[i] for i in range(len(values)) if i not in must]
    cap = capacity - wsum
    dp = [0] * (cap + 1)
    for w, v in zip(rest_w, rest_v):
        for c in range(cap, w - 1, -1):
            if dp[c - w] + v > dp[c]:
                dp[c] = dp[c - w] + v
    return vsum + dp[cap]

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
    assert knapsack_mandatory([1, 3, 4, 5], [1, 4, 5, 7], 7, [1]) == 9
    assert knapsack_mandatory([5, 5], [1, 1], 5, [0, 1]) == -1
    assert knapsack_mandatory([2, 3], [3, 4], 5, []) == 7
    assert knapsack_mandatory([2], [3], 2, [0]) == 3
    assert stdlib_only()
    print("38-mandatory OK")


if __name__ == "__main__":
    main()
