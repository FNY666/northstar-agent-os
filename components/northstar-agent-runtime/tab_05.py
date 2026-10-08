"""Coin change (tab-05), tabulation DP."""
from __future__ import annotations
import ast
VERSION = "tab-coin-change.v1"

def coin_change(coins: list, amount: int) -> int:
    if amount < 0: raise ValueError("amount must be >= 0")
    INF = amount + 1
    dp = [INF] * (amount + 1)
    dp[0] = 0
    for c in coins:
        for a in range(c, amount + 1):
            if dp[a - c] + 1 < dp[a]:
                dp[a] = dp[a - c] + 1
    return dp[amount] if dp[amount] != INF else -1

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
    assert coin_change([1, 2, 5], 11) == 3
    assert coin_change([2], 3) == -1
    assert coin_change([1], 0) == 0
    assert stdlib_only()
    print("tab-coin-change OK")

if __name__ == "__main__": main()
