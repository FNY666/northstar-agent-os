"""Fibonacci (tab-01), tabulation DP."""
from __future__ import annotations
import ast
VERSION = "tab-fibonacci.v1"

def fib_tab(n: int) -> int:
    if n < 0: raise ValueError("n must be >= 0")
    if n <= 1: return n
    dp = [0] * (n + 1)
    dp[1] = 1
    for i in range(2, n + 1):
        dp[i] = dp[i - 1] + dp[i - 2]
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
    assert fib_tab(0) == 0
    assert fib_tab(1) == 1
    assert fib_tab(10) == 55
    assert fib_tab(20) == 6765
    assert stdlib_only()
    print("tab-fibonacci OK")

if __name__ == "__main__": main()
