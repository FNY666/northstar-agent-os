"""Catalan numbers (tab-42), tabulation DP."""
from __future__ import annotations
import ast
VERSION = "tab-catalan.v1"

def catalan(n: int) -> int:
    if n < 0: raise ValueError("n must be >= 0")
    dp = [0] * (n + 1)
    dp[0] = 1
    for i in range(1, n + 1):
        total = 0
        for j in range(i):
            total += dp[j] * dp[i - 1 - j]
        dp[i] = total
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
    assert catalan(0) == 1
    assert catalan(3) == 5
    assert catalan(5) == 42
    assert stdlib_only()
    print("tab-catalan OK")

if __name__ == "__main__": main()
