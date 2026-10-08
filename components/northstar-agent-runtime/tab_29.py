"""Perfect squares (tab-29), tabulation DP."""
from __future__ import annotations
import ast
VERSION = "tab-squares.v1"

def num_squares(n: int) -> int:
    dp = [0] + [n] * n
    for i in range(1, n + 1):
        j = 1
        while j * j <= i:
            if dp[i - j * j] + 1 < dp[i]:
                dp[i] = dp[i - j * j] + 1
            j += 1
    return dp[n]

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
    assert num_squares(12) == 3
    assert num_squares(13) == 2
    assert num_squares(1) == 1
    assert stdlib_only()
    print("tab-squares OK")

if __name__ == "__main__": main()
