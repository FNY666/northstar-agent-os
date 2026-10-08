"""Partition equal subset sum (tab-15), tabulation DP."""
from __future__ import annotations
import ast
VERSION = "tab-partition.v1"

def can_partition(nums: list) -> bool:
    total = sum(nums)
    if total % 2: return False
    target = total // 2
    dp = [False] * (target + 1)
    dp[0] = True
    for x in nums:
        for t in range(target, x - 1, -1):
            if dp[t - x]:
                dp[t] = True
    return dp[target]

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
    assert can_partition([1, 5, 11, 5]) is True
    assert can_partition([1, 2, 3, 5]) is False
    assert can_partition([1]) is False
    assert stdlib_only()
    print("tab-partition OK")

if __name__ == "__main__": main()
