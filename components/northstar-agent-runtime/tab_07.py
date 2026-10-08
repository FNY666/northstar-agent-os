"""0/1 knapsack (tab-07), tabulation DP."""
from __future__ import annotations
import ast
VERSION = "tab-knapsack.v1"

def knapsack(weights: list, values: list, capacity: int) -> int:
    if capacity < 0: raise ValueError("capacity must be >= 0")
    dp = [0] * (capacity + 1)
    for w, v in zip(weights, values):
        for c in range(capacity, w - 1, -1):
            if dp[c - w] + v > dp[c]:
                dp[c] = dp[c - w] + v
    return dp[capacity]

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
    assert knapsack([1, 3, 4, 5], [1, 4, 5, 7], 7) == 9
    assert knapsack([2], [3], 1) == 0
    assert knapsack([1], [5], 1) == 5
    assert stdlib_only()
    print("tab-knapsack OK")

if __name__ == "__main__": main()
