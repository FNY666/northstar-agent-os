"""Best time to buy and sell stock (tab-39), tabulation DP."""
from __future__ import annotations
import ast
VERSION = "tab-stock1.v1"

def max_profit(prices: list) -> int:
    best = 0
    low = prices[0]
    for p in prices[1:]:
        if p - low > best: best = p - low
        if p < low: low = p
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
    assert max_profit([7, 1, 5, 3, 6, 4]) == 5
    assert max_profit([7, 6, 4, 3, 1]) == 0
    assert max_profit([1]) == 0
    assert stdlib_only()
    print("tab-stock1 OK")

if __name__ == "__main__": main()
