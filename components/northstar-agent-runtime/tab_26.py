"""Rod cutting (tab-26), tabulation DP."""
from __future__ import annotations
import ast
VERSION = "tab-rod.v1"

def rod_cut(prices: list, n: int) -> int:
    dp = [0] * (n + 1)
    for length in range(1, n + 1):
        best = 0
        for cut in range(1, length + 1):
            if cut - 1 < len(prices):
                val = prices[cut - 1] + dp[length - cut]
                if val > best: best = val
        dp[length] = best
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
    assert rod_cut([1, 5, 8, 9, 10, 17, 17, 20], 8) == 22
    assert rod_cut([1, 5, 8, 9, 10, 17, 17, 20], 4) == 10
    assert rod_cut([3], 1) == 3
    assert stdlib_only()
    print("tab-rod OK")

if __name__ == "__main__": main()
