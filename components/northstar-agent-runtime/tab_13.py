"""Longest palindromic subsequence (tab-13), tabulation DP."""
from __future__ import annotations
import ast
VERSION = "tab-lps.v1"

def longest_pal_subseq(s: str) -> int:
    n = len(s)
    if n == 0: return 0
    dp = [[0] * n for _ in range(n)]
    for i in range(n): dp[i][i] = 1
    for length in range(2, n + 1):
        for i in range(n - length + 1):
            j = i + length - 1
            if s[i] == s[j]:
                dp[i][j] = 2 if length == 2 else dp[i + 1][j - 1] + 2
            else:
                dp[i][j] = dp[i + 1][j] if dp[i + 1][j] >= dp[i][j - 1] else dp[i][j - 1]
    return dp[0][n - 1]

def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib", "typing"}
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                if a.name.split(".")[0] not in allowed: return False
        elif isinstance(n, ast.ImportFrom):
            if n.module and n.module.split(".")[0] not in allowed: return False
    return True

def main() -> None:
    assert longest_pal_subseq("bbbab") == 4
    assert longest_pal_subseq("cbbd") == 2
    assert longest_pal_subseq("") == 0
    assert longest_pal_subseq("a") == 1
    assert stdlib_only()
    print("tab-lps OK")

if __name__ == "__main__": main()
