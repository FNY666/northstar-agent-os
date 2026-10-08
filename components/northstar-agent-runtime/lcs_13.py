"""LCS of three strings (3D DP)

What this IS: LCS length over three strings with a full 3D dynamic programming table.

What this IS NOT:
* the layered variant -- see lcs_14 for O(n*m) space.
* LCS of two strings -- see lcs_01.
"""

from __future__ import annotations

import ast

#: Module version.
LCS_13_VERSION = "lcs-13.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.lcs-13.v1"


def lcs3_length(a: str, b: str, c: str) -> int:
    # O(m*n*p) time and space 3D DP.
    m, n, p = len(a), len(b), len(c)
    dp = [[[0] * (p + 1) for _ in range(n + 1)] for _ in range(m + 1)]
    for i in range(1, m + 1):
        for j in range(1, n + 1):
            for k in range(1, p + 1):
                if a[i - 1] == b[j - 1] == c[k - 1]:
                    dp[i][j][k] = dp[i - 1][j - 1][k - 1] + 1
                else:
                    dp[i][j][k] = max(dp[i - 1][j][k], dp[i][j - 1][k], dp[i][j][k - 1])
    return dp[m][n][p]

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
    assert lcs3_length("abc", "abc", "abc") == 3
    assert lcs3_length("abc", "def", "ghi") == 0
    assert lcs3_length("abcde", "ace", "ae") == 2
    assert lcs3_length("", "a", "b") == 0
    assert lcs3_length("abcd", "abce", "abcf") == 3
    assert stdlib_only()
    print("13-ok OK")


if __name__ == "__main__":
    main()
