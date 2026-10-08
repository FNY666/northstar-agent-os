"""Matrix chain multiplication (tab-25), tabulation DP."""
from __future__ import annotations
import ast
VERSION = "tab-mat-chain.v1"

def matrix_chain(dims: list) -> int:
    n = len(dims) - 1
    if n <= 1: return 0
    dp = [[0] * n for _ in range(n)]
    for length in range(2, n + 1):
        for i in range(n - length + 1):
            j = i + length - 1
            best = None
            for k in range(i, j):
                cost = dp[i][k] + dp[k + 1][j] + dims[i] * dims[k + 1] * dims[j + 1]
                if best is None or cost < best:
                    best = cost
            dp[i][j] = best
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
    assert matrix_chain([1, 2, 3, 4]) == 18
    assert matrix_chain([40, 20, 30, 10, 30]) == 26000
    assert matrix_chain([10, 20]) == 0
    assert stdlib_only()
    print("tab-mat-chain OK")

if __name__ == "__main__": main()
