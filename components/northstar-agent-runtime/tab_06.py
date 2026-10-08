"""Coin change II (tab-06), tabulation DP."""
from __future__ import annotations
import ast
VERSION = "tab-coin-change-2.v1"

def change(amount: int, coins: list) -> int:
    dp = [0] * (amount + 1)
    dp[0] = 1
    for c in coins:
        for a in range(c, amount + 1):
            dp[a] += dp[a - c]
    return dp[amount]

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
    assert change(5, [1, 2, 5]) == 4
    assert change(3, [2]) == 0
    assert change(0, [1]) == 1
    assert change(10, [10]) == 1
    assert stdlib_only()
    print("tab-coin-change-2 OK")

if __name__ == "__main__": main()
