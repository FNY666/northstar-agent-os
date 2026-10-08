"""Branch and bound knapsack

Exact 0/1 knapsack via DFS pruned by a fractional upper bound.

What this IS: branch-and-bound 0/1 knapsack with fractional-bound pruning.

What this IS NOT:
* a DP over capacity -- this searches the item tree instead.
* a heuristic -- it always finds the exact optimum.
"""

from __future__ import annotations

import ast
from typing import Dict, List, Set, Tuple

#: Module version.
KS_35_VERSION = "ks-35.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ks-35.v1"


def knapsack_branch_bound(weights, values, capacity):
    # Exact 0/1 via DFS with fractional upper bound.
    if capacity < 0:
        raise ValueError("capacity must be >= 0")
    items = sorted(
        range(len(weights)),
        key=lambda i: (values[i] / weights[i]) if weights[i] > 0 else 0.0,
        reverse=True,
    )
    best = [0]

    def bound(i, rem):
        b = 0.0
        for j in range(i, len(items)):
            k = items[j]
            w = weights[k]
            if w <= rem:
                b += values[k]
                rem -= w
            elif w > 0:
                b += values[k] * rem / w
                break
        return b

    def dfs(i, rem, val):
        if i == len(items):
            if val > best[0]:
                best[0] = val
            return
        if val + bound(i, rem) <= best[0]:
            return
        k = items[i]
        if weights[k] <= rem:
            dfs(i + 1, rem - weights[k], val + values[k])
        dfs(i + 1, rem, val)

    dfs(0, capacity, 0)
    return best[0]

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
    assert knapsack_branch_bound([1, 3, 4, 5], [1, 4, 5, 7], 7) == 9
    assert knapsack_branch_bound([], [], 5) == 0
    assert knapsack_branch_bound([5], [10], 3) == 0
    assert knapsack_branch_bound([2, 3], [3, 4], 5) == 7
    assert stdlib_only()
    print("35-branch-bound OK")


if __name__ == "__main__":
    main()
