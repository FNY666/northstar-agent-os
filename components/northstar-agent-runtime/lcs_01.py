"""LCS length (classic 2D DP)

What this IS: the textbook longest-common-subsequence length via full m*n dynamic programming table.

What this IS NOT:
* a space-optimized variant -- see lcs_02 for O(min(m,n)) space.
* a reconstruction -- see lcs_03 for the actual subsequence string.
"""

from __future__ import annotations

import ast

#: Module version.
LCS_01_VERSION = "lcs-01.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.lcs-01.v1"


def lcs_length(a: str, b: str) -> int:
    # Classic O(m*n) time / O(m*n) space DP.
    m, n = len(a), len(b)
    dp = [[0] * (n + 1) for _ in range(m + 1)]
    for i in range(1, m + 1):
        ai = a[i - 1]
        row, prow = dp[i], dp[i - 1]
        for j in range(1, n + 1):
            if ai == b[j - 1]:
                row[j] = prow[j - 1] + 1
            elif prow[j] >= row[j - 1]:
                row[j] = prow[j]
            else:
                row[j] = row[j - 1]
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
    assert lcs_length("abcde", "ace") == 3
    assert lcs_length("", "abc") == 0
    assert lcs_length("abc", "abc") == 3
    assert lcs_length("abc", "def") == 0
    assert lcs_length("AGGTAB", "GXTXAYB") == 4
    assert stdlib_only()
    print("01-ok OK")


if __name__ == "__main__":
    main()
