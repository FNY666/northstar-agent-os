"""Knapsack with exactly k items

Max value using exactly k items; -1 if impossible.

What this IS: cardinality-exact knapsack: exactly k picks.

What this IS NOT:
* an at-most-k solver -- use ks_25 for the relaxed form.
* a solver that pads with dummy items.
"""

from __future__ import annotations

import ast
from typing import Dict, List, Set, Tuple

#: Module version.
KS_28_VERSION = "ks-28.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ks-28.v1"


def knapsack_exactly_k(weights, values, capacity, k):
    # Max value using exactly k items; -1 if impossible.
    if capacity < 0 or k < 0:
        raise ValueError("capacity and k must be >= 0")
    neg = -10 ** 18
    dp = [[neg] * (capacity + 1) for _ in range(k + 1)]
    dp[0][0] = 0
    for w, v in zip(weights, values):
        for t in range(k, 0, -1):
            for c in range(capacity, w - 1, -1):
                if dp[t - 1][c - w] != neg:
                    cand = dp[t - 1][c - w] + v
                    if cand > dp[t][c]:
                        dp[t][c] = cand
    best = max(dp[k])
    return -1 if best == neg else best

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
    assert knapsack_exactly_k([1, 2, 3], [6, 10, 12], 5, 2) == 22
    assert knapsack_exactly_k([1, 2, 3], [6, 10, 12], 5, 5) == -1
    assert knapsack_exactly_k([1, 2, 3], [6, 10, 12], 5, 1) == 12
    assert knapsack_exactly_k([], [], 5, 0) == 0
    assert stdlib_only()
    print("28-exactly-k OK")


if __name__ == "__main__":
    main()
