"""Fractional knapsack (greedy)

Greedy by value density; fractions of a single item may be taken.

What this IS: the fractional knapsack solved optimally by the greedy density rule.

What this IS NOT:
* a 0/1 knapsack -- fractions are allowed here.
* valid when items are indivisible.
"""

from __future__ import annotations

import ast
from typing import Dict, List, Set, Tuple

#: Module version.
KS_02_VERSION = "ks-02.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ks-02.v1"


def fractional_knapsack(weights, values, capacity):
    # Greedy by value density; fractions of one item allowed. Optimal here.
    if capacity < 0:
        raise ValueError("capacity must be >= 0")
    order = sorted(
        range(len(weights)),
        key=lambda i: (values[i] / weights[i]) if weights[i] > 0 else 0.0,
        reverse=True,
    )
    total = 0.0
    rem = float(capacity)
    for i in order:
        w = weights[i]
        if w <= 0 or rem <= 0:
            continue
        take = min(float(w), rem)
        total += take * values[i] / w
        rem -= take
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
    assert fractional_knapsack([10, 20, 30], [60, 100, 120], 50) == 240.0
    assert fractional_knapsack([], [], 10) == 0.0
    assert fractional_knapsack([5], [10], 2) == 4.0
    assert fractional_knapsack([5], [10], 0) == 0.0
    assert stdlib_only()
    print("02-fractional OK")


if __name__ == "__main__":
    main()
