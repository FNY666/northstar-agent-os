"""Ones and zeroes

Max strings formable with m zeros and n ones.

What this IS: the classic 2D knapsack over character budgets.

What this IS NOT:
* a string matcher -- this budgets characters.
* a solver that reuses characters across strings.
"""

from __future__ import annotations

import ast
from typing import Dict, List, Set, Tuple

#: Module version.
KS_27_VERSION = "ks-27.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ks-27.v1"


def ones_zeroes(strs, m, n):
    # Max strings formable with m zeros and n ones.
    dp = [[0] * (n + 1) for _ in range(m + 1)]
    for s in strs:
        z = s.count("0")
        o = len(s) - z
        for i in range(m, z - 1, -1):
            for j in range(n, o - 1, -1):
                cand = dp[i - z][j - o] + 1
                if cand > dp[i][j]:
                    dp[i][j] = cand
    return dp[m][n]

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
    assert ones_zeroes(["10", "0001", "111001", "1", "0"], 5, 3) == 4
    assert ones_zeroes(["10", "0", "1"], 1, 1) == 2
    assert ones_zeroes([], 5, 3) == 0
    assert ones_zeroes(["11"], 1, 1) == 0
    assert stdlib_only()
    print("27-ones-zeroes OK")


if __name__ == "__main__":
    main()
