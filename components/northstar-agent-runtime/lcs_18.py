"""Longest repeating subsequence

What this IS: longest subsequence occurring at least twice: LCS(s, s) with i != j.

What this IS NOT:
* longest repeated substring -- contiguity is not required here.
* plain LCS of two inputs -- see lcs_01.
"""

from __future__ import annotations

import ast

#: Module version.
LCS_18_VERSION = "lcs-18.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.lcs-18.v1"


def longest_repeating_subseq(s: str) -> int:
    # Same DP as LCS(s, s) but diagonal matches are forbidden.
    n = len(s)
    dp = [[0] * (n + 1) for _ in range(n + 1)]
    for i in range(1, n + 1):
        for j in range(1, n + 1):
            if s[i - 1] == s[j - 1] and i != j:
                dp[i][j] = dp[i - 1][j - 1] + 1
            else:
                dp[i][j] = dp[i - 1][j] if dp[i - 1][j] >= dp[i][j - 1] else dp[i][j - 1]
    return dp[n][n]

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
    assert longest_repeating_subseq("aabebcdd") == 3
    assert longest_repeating_subseq("aabb") == 2
    assert longest_repeating_subseq("abc") == 0
    assert longest_repeating_subseq("") == 0
    assert longest_repeating_subseq("aaaa") == 3
    assert stdlib_only()
    print("18-ok OK")


if __name__ == "__main__":
    main()
