"""Maximal square (tab-20), tabulation DP."""
from __future__ import annotations
import ast
VERSION = "tab-maxsquare.v1"

def maximal_square(matrix: list) -> int:
    if not matrix or not matrix[0]: return 0
    m, n = len(matrix), len(matrix[0])
    dp = [0] * (n + 1)
    best = 0
    for i in range(1, m + 1):
        prev = 0
        for j in range(1, n + 1):
            cur = dp[j]
            if matrix[i - 1][j - 1] == "1":
                dp[j] = min(dp[j], dp[j - 1], prev) + 1
                if dp[j] > best: best = dp[j]
            else:
                dp[j] = 0
            prev = cur
    return best * best

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
    assert maximal_square([["1", "0", "1", "0", "0"], ["1", "0", "1", "1", "1"], ["1", "1", "1", "1", "1"], ["1", "0", "0", "1", "0"]]) == 4
    assert maximal_square([["0"]]) == 0
    assert maximal_square([["1"]]) == 1
    assert stdlib_only()
    print("tab-maxsquare OK")

if __name__ == "__main__": main()
