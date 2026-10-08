"""Burst balloons (tab-24), tabulation DP."""
from __future__ import annotations
import ast
VERSION = "tab-balloons.v1"

def max_coins(nums: list) -> int:
    vals = [1] + [x for x in nums if x > 0] + [1]
    n = len(vals)
    dp = [[0] * n for _ in range(n)]
    for length in range(2, n):
        for left in range(n - length):
            right = left + length
            for k in range(left + 1, right):
                total = vals[left] * vals[k] * vals[right] + dp[left][k] + dp[k][right]
                if total > dp[left][right]:
                    dp[left][right] = total
    return dp[0][n - 1]

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
    assert max_coins([3, 1, 5, 8]) == 167
    assert max_coins([1, 5]) == 10
    assert max_coins([]) == 0
    assert stdlib_only()
    print("tab-balloons OK")

if __name__ == "__main__": main()
