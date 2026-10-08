"""Tree knapsack (prerequisites)

Items form a forest; taking a child requires taking its parent.

What this IS: knapsack with precedence constraints on a forest, via tree DP.

What this IS NOT:
* a plain 0/1 knapsack -- prerequisites change the structure.
* valid for cyclic prerequisite graphs.
"""

from __future__ import annotations

import ast
from typing import Dict, List, Set, Tuple

#: Module version.
KS_16_VERSION = "ks-16.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ks-16.v1"


def tree_knapsack(weights, values, parents, capacity):
    # parents[i] = parent index or -1; a child needs its parent taken.
    if capacity < 0:
        raise ValueError("capacity must be >= 0")
    n = len(weights)
    neg = -10 ** 18
    children = [[] for _ in range(n)]
    roots = []
    for i, p in enumerate(parents):
        if p is None or p < 0:
            roots.append(i)
        else:
            children[p].append(i)

    def dfs(u):
        # best value in u's subtree using c capacity, must include u
        dp = [neg] * (capacity + 1)
        wu = weights[u]
        for c in range(wu, capacity + 1):
            dp[c] = values[u]
        for ch in children[u]:
            cdf = dfs(ch)
            merged = dp[:]
            for c in range(capacity + 1):
                for k in range(c + 1):
                    if dp[c - k] != neg and cdf[k] != neg:
                        cand = dp[c - k] + cdf[k]
                        if cand > merged[c]:
                            merged[c] = cand
            dp = merged
        return dp

    total = [0] * (capacity + 1)
    for r in roots:
        rdf = dfs(r)
        merged = total[:]
        for c in range(capacity + 1):
            for k in range(c + 1):
                if rdf[k] != neg:
                    cand = total[c - k] + rdf[k]
                    if cand > merged[c]:
                        merged[c] = cand
        total = merged
    return max(total)

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
    assert tree_knapsack([2, 1], [3, 2], [-1, 0], 3) == 5
    assert tree_knapsack([2, 1], [3, 2], [-1, 0], 2) == 3
    assert tree_knapsack([2, 1], [3, 2], [-1, 0], 1) == 0
    assert tree_knapsack([], [], [], 5) == 0
    assert stdlib_only()
    print("16-tree OK")


if __name__ == "__main__":
    main()
