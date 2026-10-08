"""Dungeon game (tab-35), tabulation DP."""
from __future__ import annotations
import ast
VERSION = "tab-dungeon.v1"

def min_hp(dungeon: list) -> int:
    m, n = len(dungeon), len(dungeon[0])
    dp = [[0] * n for _ in range(m)]
    for i in range(m - 1, -1, -1):
        for j in range(n - 1, -1, -1):
            if i == m - 1 and j == n - 1:
                need = 1 - dungeon[i][j]
            elif i == m - 1:
                need = dp[i][j + 1] - dungeon[i][j]
            elif j == n - 1:
                need = dp[i + 1][j] - dungeon[i][j]
            else:
                need = min(dp[i + 1][j], dp[i][j + 1]) - dungeon[i][j]
            dp[i][j] = need if need > 1 else 1
    return dp[0][0]

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
    assert min_hp([[-2, -3, 3], [-5, -10, 1], [10, 30, -5]]) == 7
    assert min_hp([[0]]) == 1
    assert min_hp([[-3]]) == 4
    assert stdlib_only()
    print("tab-dungeon OK")

if __name__ == "__main__": main()
