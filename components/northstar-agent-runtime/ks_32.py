"""Guarded 0/1 knapsack (fail-closed)

0/1 knapsack that rejects negative or mismatched input.

What this IS: fail-closed 0/1 knapsack: bad input raises instead of computing.

What this IS NOT:
* a lenient solver -- invalid input is an error here.
* a sanitizer -- callers must pass clean input.
"""

from __future__ import annotations

import ast
from typing import Dict, List, Set, Tuple

#: Module version.
KS_32_VERSION = "ks-32.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ks-32.v1"


def knapsack_guarded(weights, values, capacity):
    # 0/1 knapsack that fails closed on bad input.
    if not isinstance(capacity, int) or capacity < 0:
        raise ValueError("capacity must be a non-negative int")
    if len(weights) != len(values):
        raise ValueError("weights and values length mismatch")
    for w, v in zip(weights, values):
        if w < 0 or v < 0:
            raise ValueError("weights and values must be >= 0")
    dp = [0] * (capacity + 1)
    for w, v in zip(weights, values):
        for c in range(capacity, w - 1, -1):
            if dp[c - w] + v > dp[c]:
                dp[c] = dp[c - w] + v
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
    assert knapsack_guarded([1, 3, 4, 5], [1, 4, 5, 7], 7) == 9
    try:
        knapsack_guarded([1], [1], -1)
        raise AssertionError("should have raised")
    except ValueError:
        pass
    try:
        knapsack_guarded([-1], [1], 5)
        raise AssertionError("should have raised")
    except ValueError:
        pass
    try:
        knapsack_guarded([1], [1, 2], 5)
        raise AssertionError("should have raised")
    except ValueError:
        pass
    assert stdlib_only()
    print("32-guarded OK")


if __name__ == "__main__":
    main()
