"""Binomial coefficient (tab-41), tabulation DP."""
from __future__ import annotations
import ast
VERSION = "tab-ncr.v1"

def ncr(n: int, r: int) -> int:
    if r < 0 or r > n: return 0
    r = min(r, n - r)
    dp = [0] * (r + 1)
    dp[0] = 1
    for i in range(1, n + 1):
        upper = min(i, r)
        for j in range(upper, 0, -1):
            dp[j] += dp[j - 1]
    return dp[r]

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
    assert ncr(5, 2) == 10
    assert ncr(10, 3) == 120
    assert ncr(0, 0) == 1
    assert ncr(5, 6) == 0
    assert stdlib_only()
    print("tab-ncr OK")

if __name__ == "__main__": main()
