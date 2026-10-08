"""Wildcard matching (tab-45), tabulation DP."""
from __future__ import annotations
import ast
VERSION = "tab-wildcard.v1"

def is_match_wild(s: str, p: str) -> bool:
    m, n = len(s), len(p)
    dp = [[False] * (n + 1) for _ in range(m + 1)]
    dp[0][0] = True
    for j in range(1, n + 1):
        if p[j - 1] == "*":
            dp[0][j] = dp[0][j - 1]
    for i in range(1, m + 1):
        for j in range(1, n + 1):
            if p[j - 1] == "*":
                dp[i][j] = dp[i][j - 1] or dp[i - 1][j]
            elif p[j - 1] in (s[i - 1], "?"):
                dp[i][j] = dp[i - 1][j - 1]
    return dp[m][n]

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
    assert is_match_wild("aa", "a") is False
    assert is_match_wild("aa", "*") is True
    assert is_match_wild("cb", "?a") is False
    assert is_match_wild("adceb", "*a*b") is True
    assert stdlib_only()
    print("tab-wildcard OK")

if __name__ == "__main__": main()
