"""Best time to buy and sell stock II (tab-40), tabulation DP."""
from __future__ import annotations
import ast
VERSION = "tab-stock2.v1"

def max_profit2(prices: list) -> int:
    profit = 0
    for i in range(1, len(prices)):
        if prices[i] > prices[i - 1]:
            profit += prices[i] - prices[i - 1]
    return profit

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
    assert max_profit2([7, 1, 5, 3, 6, 4]) == 7
    assert max_profit2([1, 2, 3, 4, 5]) == 4
    assert max_profit2([7, 6, 4, 3, 1]) == 0
    assert stdlib_only()
    print("tab-stock2 OK")

if __name__ == "__main__": main()
