"""Longest common substring (tab-31), tabulation DP."""
from __future__ import annotations
import ast
VERSION = "tab-lcsubstr.v1"

def longest_common_substring(a: str, b: str) -> int:
    m, n = len(a), len(b)
    dp = [0] * (n + 1)
    best = 0
    for i in range(1, m + 1):
        prev = 0
        for j in range(1, n + 1):
            cur = dp[j]
            if a[i - 1] == b[j - 1]:
                dp[j] = prev + 1
                if dp[j] > best: best = dp[j]
            else:
                dp[j] = 0
            prev = cur
    return best

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
    assert longest_common_substring("abcdxyz", "xyzabcd") == 4
    assert longest_common_substring("abc", "def") == 0
    assert longest_common_substring("abc", "abc") == 3
    assert stdlib_only()
    print("tab-lcsubstr OK")

if __name__ == "__main__": main()
