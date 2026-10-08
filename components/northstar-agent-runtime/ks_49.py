"""Knapsack solution validator

Check a claimed solution: indices valid, unique, within capacity.

What this IS: a fail-closed checker for knapsack solutions.

What this IS NOT:
* a solver -- this only validates claimed solutions.
* an optimality checker -- it verifies feasibility, not optimality.
"""

from __future__ import annotations

import ast
from typing import Dict, List, Set, Tuple

#: Module version.
KS_49_VERSION = "ks-49.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ks-49.v1"


def validate_knapsack(weights, values, capacity, chosen):
    # Returns (ok, info): ok bool, info = value or error string.
    if capacity < 0:
        return (False, "negative capacity")
    n = len(weights)
    if any(i < 0 or i >= n for i in chosen):
        return (False, "index out of range")
    if len(set(chosen)) != len(chosen):
        return (False, "duplicate index")
    wsum = sum(weights[i] for i in chosen)
    if wsum > capacity:
        return (False, "over capacity")
    return (True, sum(values[i] for i in chosen))

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
    assert validate_knapsack([1, 3, 4], [1, 4, 5], 7, [1, 2]) == (True, 9)
    assert validate_knapsack([1, 3, 4], [1, 4, 5], 5, [1, 2]) == (False, "over capacity")
    assert validate_knapsack([1], [1], 5, [1]) == (False, "index out of range")
    assert validate_knapsack([1], [1], 5, [0, 0]) == (False, "duplicate index")
    assert stdlib_only()
    print("49-validator OK")


if __name__ == "__main__":
    main()
