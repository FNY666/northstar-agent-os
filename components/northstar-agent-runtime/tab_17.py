"""Unique paths with obstacles (tab-17), tabulation DP."""
from __future__ import annotations
import ast
VERSION = "tab-paths-obst.v1"

def unique_paths_obstacles(grid: list) -> int:
    if not grid or not grid[0]: return 0
    m, n = len(grid), len(grid[0])
    dp = [0] * n
    dp[0] = 1 if grid[0][0] == 0 else 0
    for i in range(m):
        for j in range(n):
            if grid[i][j] == 1:
                dp[j] = 0
            elif j > 0:
                dp[j] += dp[j - 1]
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
    assert unique_paths_obstacles([[0, 0, 0], [0, 1, 0], [0, 0, 0]]) == 2
    assert unique_paths_obstacles([[0, 1], [0, 0]]) == 1
    assert unique_paths_obstacles([[1]]) == 0
    assert stdlib_only()
    print("tab-paths-obst OK")

if __name__ == "__main__": main()
