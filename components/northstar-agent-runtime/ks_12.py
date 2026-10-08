"""Bounded knapsack (binary splitting)

Each item i usable at most counts[i] times.

What this IS: bounded knapsack via binary splitting into 0/1 items.

What this IS NOT:
* an unbounded knapsack -- copies are limited here.
* efficient for huge counts without splitting.
"""

from __future__ import annotations

import ast
from typing import Dict, List, Set, Tuple

#: Module version.
KS_12_VERSION = "ks-12.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ks-12.v1"


def bounded_knapsack(weights, values, counts, capacity):
    # Each item i usable at most counts[i] times; binary splitting.
    if capacity < 0:
        raise ValueError("capacity must be >= 0")
    items = []
    for w, v, k in zip(weights, values, counts):
        if w < 0 or v < 0 or k < 0:
            raise ValueError("inputs must be >= 0")
        p = 1
        while k > 0:
            take = min(p, k)
            items.append((w * take, v * take))
            k -= take
            p *= 2
    dp = [0] * (capacity + 1)
    for w, v in items:
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
    assert bounded_knapsack([2], [3], [3], 5) == 6
    assert bounded_knapsack([2], [3], [1], 5) == 3
    assert bounded_knapsack([3], [4], [2], 5) == 4
    assert bounded_knapsack([], [], [], 5) == 0
    assert stdlib_only()
    print("12-bounded OK")


if __name__ == "__main__":
    main()
