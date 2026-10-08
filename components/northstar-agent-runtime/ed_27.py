"""Levenshtein with full matrix returned

Classic edit distance that also returns the DP matrix for inspection.

What this IS: Wagner-Fischer returning (distance, matrix).

What this IS NOT:
* distance only -- ed_01 discards the matrix.
* an alignment -- ed_26/ed_28 backtrace through it.
"""

from __future__ import annotations

import ast
from typing import Dict, List, Tuple

#: Module version.
ED_27_VERSION = "ed-27.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ed-27.v1"


def levenshtein_matrix(a: str, b: str) -> Tuple[int, List[List[int]]]:
    """Levenshtein distance plus the full DP matrix."""
    if not isinstance(a, str) or not isinstance(b, str):
        raise TypeError("inputs must be str")
    m, n = len(a), len(b)
    dp = [[0] * (n + 1) for _ in range(m + 1)]
    for i in range(m + 1):
        dp[i][0] = i
    for j in range(n + 1):
        dp[0][j] = j
    for i in range(1, m + 1):
        ai = a[i - 1]
        for j in range(1, n + 1):
            cost = 0 if ai == b[j - 1] else 1
            dp[i][j] = min(dp[i - 1][j] + 1, dp[i][j - 1] + 1,
                           dp[i - 1][j - 1] + cost)
    return (dp[m][n], dp)

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
    d, mat = levenshtein_matrix("kitten", "sitting")
    assert d == 3
    assert mat[0] == list(range(8))
    assert [row[0] for row in mat] == list(range(7))
    assert mat[6][7] == 3
    d2, _ = levenshtein_matrix("", "")
    assert d2 == 0
    try:
        levenshtein_matrix("a", 1)
    except TypeError:
        pass
    else:
        raise AssertionError("expected TypeError")
    assert stdlib_only()
    print("27-matrix OK")


if __name__ == "__main__":
    main()
