"""Minimum falling path sum (tab-36), tabulation DP."""
from __future__ import annotations
import ast
VERSION = "tab-falling.v1"

def min_falling(matrix: list) -> int:
    n = len(matrix)
    dp = list(matrix[0])
    for i in range(1, n):
        new = [0] * n
        for j in range(n):
            best = dp[j]
            if j > 0 and dp[j - 1] < best: best = dp[j - 1]
            if j < n - 1 and dp[j + 1] < best: best = dp[j + 1]
            new[j] = matrix[i][j] + best
        dp = new
    return min(dp)

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
    assert min_falling([[2, 1, 3], [6, 5, 4], [7, 8, 9]]) == 13
    assert min_falling([[-19, 57], [-40, -5]]) == -59
    assert min_falling([[5]]) == 5
    assert stdlib_only()
    print("tab-falling OK")

if __name__ == "__main__": main()
