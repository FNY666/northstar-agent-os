"""Unbounded knapsack (tab-08), tabulation DP."""
from __future__ import annotations
import ast
VERSION = "tab-unbounded.v1"

def unbounded_knapsack(weights: list, values: list, capacity: int) -> int:
    dp = [0] * (capacity + 1)
    for c in range(1, capacity + 1):
        best = 0
        for w, v in zip(weights, values):
            if w <= c and dp[c - w] + v > best:
                best = dp[c - w] + v
        dp[c] = best
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
    assert unbounded_knapsack([1, 3, 4], [15, 50, 60], 5) == 80
    assert unbounded_knapsack([2], [3], 1) == 0
    assert unbounded_knapsack([1], [5], 3) == 15
    assert stdlib_only()
    print("tab-unbounded OK")

if __name__ == "__main__": main()
