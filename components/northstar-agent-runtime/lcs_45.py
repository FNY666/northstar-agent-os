"""LCS via diagonal wavefront

What this IS: DP evaluated along anti-diagonals (parallel-friendly order), same result.

What this IS NOT:
* row-major DP -- see lcs_01 for the classic order.
* banded DP -- see lcs_46.
"""

from __future__ import annotations

import ast

#: Module version.
LCS_45_VERSION = "lcs-45.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.lcs-45.v1"


def lcs_wavefront(a: str, b: str) -> int:
    # Cells (i, j) with i + j == s are independent: fill diagonal by diagonal.
    m, n = len(a), len(b)
    dp = [[0] * (n + 1) for _ in range(m + 1)]
    for s in range(2, m + n + 1):
        for i in range(1, m + 1):
            j = s - i
            if 1 <= j <= n:
                if a[i - 1] == b[j - 1]:
                    dp[i][j] = dp[i - 1][j - 1] + 1
                else:
                    dp[i][j] = dp[i - 1][j] if dp[i - 1][j] >= dp[i][j - 1] else dp[i][j - 1]
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
    assert lcs_wavefront("abcde", "ace") == 3
    assert lcs_wavefront("", "abc") == 0
    assert lcs_wavefront("abc", "abc") == 3
    assert lcs_wavefront("abc", "def") == 0
    assert lcs_wavefront("AGGTAB", "GXTXAYB") == 4
    assert stdlib_only()
    print("45-ok OK")


if __name__ == "__main__":
    main()
