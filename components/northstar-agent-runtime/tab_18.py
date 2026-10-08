"""Minimum path sum (tab-18), tabulation DP."""
from __future__ import annotations
import ast
VERSION = "tab-minpath.v1"

def min_path_sum(grid: list) -> int:
    m, n = len(grid), len(grid[0])
    dp = [0] * n
    for i in range(m):
        for j in range(n):
            if i == 0 and j == 0:
                dp[j] = grid[0][0]
            elif i == 0:
                dp[j] = dp[j - 1] + grid[i][j]
            elif j == 0:
                dp[j] = dp[j] + grid[i][j]
            else:
                dp[j] = min(dp[j], dp[j - 1]) + grid[i][j]
    return dp[n - 1]

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
    assert min_path_sum([[1, 3, 1], [1, 5, 1], [4, 2, 1]]) == 7
    assert min_path_sum([[1, 2, 3], [4, 5, 6]]) == 12
    assert min_path_sum([[5]]) == 5
    assert stdlib_only()
    print("tab-minpath OK")

if __name__ == "__main__": main()
