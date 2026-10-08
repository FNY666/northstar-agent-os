"""Greedy by value (heuristic)

Take highest-value items first; fast but not optimal.

What this IS: a greedy heuristic for 0/1 knapsack: a lower bound, not the optimum.

What this IS NOT:
* an exact solver -- greedy can be arbitrarily bad here.
* a density-greedy -- this sorts by raw value.
"""

from __future__ import annotations

import ast
from typing import Dict, List, Set, Tuple

#: Module version.
KS_34_VERSION = "ks-34.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ks-34.v1"


def knapsack_greedy_value(weights, values, capacity):
    # Heuristic: take highest-value items first. NOT optimal in general.
    if capacity < 0:
        raise ValueError("capacity must be >= 0")
    order = sorted(range(len(weights)), key=lambda i: values[i], reverse=True)
    total = 0
    rem = capacity
    for i in order:
        if weights[i] <= rem:
            total += values[i]
            rem -= weights[i]
    return total

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
    assert knapsack_greedy_value([5, 4, 3], [10, 9, 8], 7) == 10
    assert knapsack_greedy_value([1, 3, 4, 5], [1, 4, 5, 7], 7) <= 9
    assert knapsack_greedy_value([], [], 5) == 0
    assert knapsack_greedy_value([5], [10], 3) == 0
    assert stdlib_only()
    print("34-greedy-value OK")


if __name__ == "__main__":
    main()
