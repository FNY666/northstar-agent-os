"""Minimum ASCII delete sum (tab-50), tabulation DP."""
from __future__ import annotations
import ast
VERSION = "tab-asciidelete.v1"

def min_delete_sum(s1: str, s2: str) -> int:
    m, n = len(s1), len(s2)
    dp = [0] * (n + 1)
    for j in range(1, n + 1):
        dp[j] = dp[j - 1] + ord(s2[j - 1])
    for i in range(1, m + 1):
        prev = dp[0]
        dp[0] += ord(s1[i - 1])
        for j in range(1, n + 1):
            cur = dp[j]
            if s1[i - 1] == s2[j - 1]:
                dp[j] = prev
            else:
                dp[j] = min(prev + ord(s1[i - 1]) + ord(s2[j - 1]),
                            dp[j] + ord(s1[i - 1]),
                            dp[j - 1] + ord(s2[j - 1]))
            prev = cur
    return dp[n]

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
    assert min_delete_sum("sea", "eat") == 231
    assert min_delete_sum("delete", "leet") == 403
    assert min_delete_sum("", "abc") == 294
    assert stdlib_only()
    print("tab-asciidelete OK")

if __name__ == "__main__": main()
