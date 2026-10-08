"""Fractional knapsack with recovery

Fractional knapsack reporting (index, amount taken) per item.

What this IS: fractional knapsack with a full take plan, not just the value.

What this IS NOT:
* a value-only solver -- use ks_02 when the plan is unneeded.
* an integral solution -- fractions are the point here.
"""

from __future__ import annotations

import ast
from typing import Dict, List, Set, Tuple

#: Module version.
KS_31_VERSION = "ks-31.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ks-31.v1"


def fractional_with_items(weights, values, capacity):
    # Returns (max_value, [(index, amount_taken), ...]).
    if capacity < 0:
        raise ValueError("capacity must be >= 0")
    order = sorted(
        range(len(weights)),
        key=lambda i: (values[i] / weights[i]) if weights[i] > 0 else -1.0,
        reverse=True,
    )
    taken = []
    total = 0.0
    rem = float(capacity)
    for i in order:
        w = weights[i]
        if w <= 0 or rem <= 0:
            continue
        take = min(float(w), rem)
        taken.append((i, take))
        total += take * values[i] / w
        rem -= take
    return total, taken

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
    total, taken = fractional_with_items([10, 20, 30], [60, 100, 120], 50)
    assert total == 240.0
    assert taken == [(0, 10.0), (1, 20.0), (2, 20.0)]
    assert fractional_with_items([], [], 5) == (0.0, [])
    t2, _ = fractional_with_items([5], [10], 0)
    assert t2 == 0.0
    assert stdlib_only()
    print("31-frac-recovery OK")


if __name__ == "__main__":
    main()
