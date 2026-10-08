"""0/1 knapsack (memoized recursion)

Classic 0/1 knapsack via top-down memoized recursion.

What this IS: top-down 0/1 knapsack with lru_cache memoization.

What this IS NOT:
* the iterative DP -- this recurses, so deep inputs may hit limits.
* a space-optimized solver -- the cache costs O(n*C).
"""

from __future__ import annotations

import ast
from functools import lru_cache

from typing import Dict, List, Set, Tuple

#: Module version.
KS_24_VERSION = "ks-24.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ks-24.v1"


def knapsack_memo(weights, values, capacity):
    # 0/1 knapsack via memoized recursion.
    if capacity < 0:
        raise ValueError("capacity must be >= 0")
    w = tuple(weights)
    v = tuple(values)

    @lru_cache(maxsize=None)
    def f(i, c):
        if i == len(w) or c <= 0:
            return 0
        best = f(i + 1, c)
        if w[i] <= c:
            cand = f(i + 1, c - w[i]) + v[i]
            if cand > best:
                best = cand
        return best

    return f(0, capacity)

def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "pathlib", "typing", "functools"}
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
    assert knapsack_memo([1, 3, 4, 5], [1, 4, 5, 7], 7) == 9
    assert knapsack_memo([], [], 10) == 0
    assert knapsack_memo([5], [10], 4) == 0
    assert knapsack_memo([2, 2], [3, 5], 2) == 5
    assert stdlib_only()
    print("24-memo OK")


if __name__ == "__main__":
    main()
