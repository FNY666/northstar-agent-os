"""Longest increasing subsequence (tab-10), tabulation DP."""
from __future__ import annotations
import ast
VERSION = "tab-lis.v1"

def lis(nums: list) -> int:
    if not nums: return 0
    dp = [1] * len(nums)
    for i in range(1, len(nums)):
        for j in range(i):
            if nums[j] < nums[i] and dp[j] + 1 > dp[i]:
                dp[i] = dp[j] + 1
    return max(dp)

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
    assert lis([10, 9, 2, 5, 3, 7, 101, 18]) == 4
    assert lis([0, 1, 0, 3, 2, 3]) == 4
    assert lis([7, 7, 7]) == 1
    assert lis([]) == 0
    assert stdlib_only()
    print("tab-lis OK")

if __name__ == "__main__": main()
