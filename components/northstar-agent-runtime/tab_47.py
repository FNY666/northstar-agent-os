"""Count subsets with sum K (tab-47), tabulation DP."""
from __future__ import annotations
import ast
VERSION = "tab-countsubset.v1"

def count_subsets(nums: list, k: int) -> int:
    dp = [0] * (k + 1)
    dp[0] = 1
    for x in nums:
        for t in range(k, x - 1, -1):
            dp[t] += dp[t - x]
    return dp[k]

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
    assert count_subsets([1, 2, 3, 3], 6) == 3
    assert count_subsets([1, 1, 1], 2) == 3
    assert count_subsets([2, 3, 5], 0) == 1
    assert stdlib_only()
    print("tab-countsubset OK")

if __name__ == "__main__": main()
