"""OSA with custom transposition cost

Optimal string alignment where a transposition has its own price.

What this IS: OSA with transpose_cost for adjacent swaps (default 1.0).

What this IS NOT:
* ed_23 -- that customizes substitution, this customizes transposition.
* true Damerau-Levenshtein -- still the restricted variant.
"""

from __future__ import annotations

import ast
from typing import Dict, List, Tuple

#: Module version.
ED_37_VERSION = "ed-37.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ed-37.v1"


def osa_transpose_weighted(
    a: str, b: str, transpose_cost: float = 1.0
) -> float:
    """OSA distance with a custom adjacent-transposition cost."""
    if not isinstance(a, str) or not isinstance(b, str):
        raise TypeError("inputs must be str")
    if transpose_cost < 0:
        raise ValueError("transpose_cost must be >= 0")
    m, n = len(a), len(b)
    dp = [[0.0] * (n + 1) for _ in range(m + 1)]
    for i in range(m + 1):
        dp[i][0] = float(i)
    for j in range(n + 1):
        dp[0][j] = float(j)
    for i in range(1, m + 1):
        for j in range(1, n + 1):
            cost = 0.0 if a[i - 1] == b[j - 1] else 1.0
            dp[i][j] = min(dp[i - 1][j] + 1.0, dp[i][j - 1] + 1.0,
                           dp[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                dp[i][j] = min(dp[i][j], dp[i - 2][j - 2] + transpose_cost)
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
    assert osa_transpose_weighted("abcd", "acbd") == 1.0
    assert osa_transpose_weighted("abcd", "acbd", transpose_cost=0.5) == 0.5
    assert osa_transpose_weighted("ab", "ba", transpose_cost=2.0) == 2.0
    assert osa_transpose_weighted("abc", "abc") == 0.0
    try:
        osa_transpose_weighted("a", "b", transpose_cost=-1.0)
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError")
    assert stdlib_only()
    print("37-osa-transpose OK")


if __name__ == "__main__":
    main()
