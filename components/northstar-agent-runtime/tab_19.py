"""Triangle minimum path (tab-19), tabulation DP."""
from __future__ import annotations
import ast
VERSION = "tab-triangle.v1"

def triangle_min(triangle: list) -> int:
    dp = list(triangle[-1])
    for row in reversed(triangle[:-1]):
        for i in range(len(row)):
            dp[i] = row[i] + (dp[i] if dp[i] <= dp[i + 1] else dp[i + 1])
    return dp[0]

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
    assert triangle_min([[2], [3, 4], [6, 5, 7], [4, 1, 8, 3]]) == 11
    assert triangle_min([[-10]]) == -10
    assert stdlib_only()
    print("tab-triangle OK")

if __name__ == "__main__": main()
