"""Knapsack benchmark harness

Compare exact 0/1 DP against greedy-by-value on a fixed instance.

What this IS: a red-vs-blue mini benchmark: exact DP against the greedy heuristic.

What this IS NOT:
* a general benchmark suite -- one fixed instance only.
* a proof about other instances -- the gap is instance-specific.
"""

from __future__ import annotations

import ast
from typing import Dict, List, Set, Tuple

#: Module version.
KS_50_VERSION = "ks-50.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ks-50.v1"


def knapsack_benchmark():
    # Compare exact 0/1 DP vs greedy-by-value on a fixed instance.
    weights = [5, 4, 3]
    values = [10, 9, 8]
    capacity = 7

    def exact():
        dp = [0] * (capacity + 1)
        for w, v in zip(weights, values):
            for c in range(capacity, w - 1, -1):
                if dp[c - w] + v > dp[c]:
                    dp[c] = dp[c - w] + v
        return dp[capacity]

    def greedy():
        order = sorted(range(len(weights)), key=lambda i: values[i], reverse=True)
        total, rem = 0, capacity
        for i in order:
            if weights[i] <= rem:
                total += values[i]
                rem -= weights[i]
        return total

    opt = exact()
    gr = greedy()
    return {"optimal": opt, "greedy": gr, "gap": opt - gr}

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
    r = knapsack_benchmark()
    assert r["optimal"] == 17
    assert r["greedy"] == 10
    assert r["gap"] == 7
    assert r["gap"] >= 0
    assert stdlib_only()
    print("50-benchmark OK")


if __name__ == "__main__":
    main()
