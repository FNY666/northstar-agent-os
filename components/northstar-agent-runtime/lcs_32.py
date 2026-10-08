"""Minimum ASCII delete sum

What this IS: weighted LCS: min sum of deleted char codes so the strings become equal.

What this IS NOT:
* unweighted delete count -- see lcs_16.
* plain LCS length -- see lcs_01.
"""

from __future__ import annotations

import ast

#: Module version.
LCS_32_VERSION = "lcs-32.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.lcs-32.v1"


def min_delete_sum(s1: str, s2: str) -> int:
    # Maximize the ASCII weight of the kept common subsequence.
    m, n = len(s1), len(s2)
    dp = [[0] * (n + 1) for _ in range(m + 1)]
    for i in range(1, m + 1):
        for j in range(1, n + 1):
            if s1[i - 1] == s2[j - 1]:
                dp[i][j] = dp[i - 1][j - 1] + ord(s1[i - 1])
            else:
                dp[i][j] = dp[i - 1][j] if dp[i - 1][j] >= dp[i][j - 1] else dp[i][j - 1]
    total = sum(map(ord, s1)) + sum(map(ord, s2))
    return total - 2 * dp[m][n]

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
    assert min_delete_sum("sea", "eat") == 231
    assert min_delete_sum("delete", "leet") == 403
    assert min_delete_sum("", "abc") == 294
    assert min_delete_sum("abc", "abc") == 0
    assert min_delete_sum("a", "b") == 195
    assert stdlib_only()
    print("32-ok OK")


if __name__ == "__main__":
    main()
