"""Palindromic substrings (tab-12), tabulation DP."""
from __future__ import annotations
import ast
VERSION = "tab-pal-sub.v1"

def count_substrings(s: str) -> int:
    n = len(s)
    dp = [[False] * n for _ in range(n)]
    count = 0
    for end in range(n):
        for start in range(end + 1):
            if s[start] == s[end] and (end - start <= 1 or dp[start + 1][end - 1]):
                dp[start][end] = True
                count += 1
    return count

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
    assert count_substrings("abc") == 3
    assert count_substrings("aaa") == 6
    assert count_substrings("") == 0
    assert count_substrings("a") == 1
    assert stdlib_only()
    print("tab-pal-sub OK")

if __name__ == "__main__": main()
