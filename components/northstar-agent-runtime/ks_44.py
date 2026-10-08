"""Stochastic knapsack (mock)

Items have success probabilities; greedy by expected density.

What this IS: a mock stochastic knapsack: expected-value greedy, not optimal.

What this IS NOT:
* an exact stochastic solver -- this is a heuristic.
* a risk-averse optimizer -- it maximizes expectation only.
"""

from __future__ import annotations

import ast
from typing import Dict, List, Set, Tuple

#: Module version.
KS_44_VERSION = "ks-44.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ks-44.v1"


def knapsack_stochastic(weights, values, probs, capacity):
    # Mock: greedy by expected value density. Not optimal in general.
    if capacity < 0:
        raise ValueError("capacity must be >= 0")
    exp = [v * p for v, p in zip(values, probs)]
    order = sorted(
        range(len(weights)),
        key=lambda i: (exp[i] / weights[i]) if weights[i] > 0 else 0.0,
        reverse=True,
    )
    total = 0.0
    rem = capacity
    for i in order:
        if weights[i] <= rem:
            total += exp[i]
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
    assert knapsack_stochastic([2, 3], [10, 12], [0.5, 1.0], 3) == 12.0
    assert knapsack_stochastic([], [], [], 5) == 0.0
    assert knapsack_stochastic([5], [10], [0.5], 3) == 0.0
    assert knapsack_stochastic([1], [4], [0.25], 1) == 1.0
    assert stdlib_only()
    print("44-stochastic OK")


if __name__ == "__main__":
    main()
