"""Target sum (tab-27), tabulation DP."""
from __future__ import annotations
import ast
VERSION = "tab-target.v1"

def find_target(nums: list, target: int) -> int:
    total = sum(nums)
    if abs(target) > total or (total + target) % 2: return 0
    s = (total + target) // 2
    dp = [0] * (s + 1)
    dp[0] = 1
    for x in nums:
        for t in range(s, x - 1, -1):
            dp[t] += dp[t - x]
    return dp[s]

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
    assert find_target([1, 1, 1, 1, 1], 3) == 5
    assert find_target([1], 1) == 1
    assert find_target([1, 2, 7, 1, 5], 9) == 0
    assert stdlib_only()
    print("tab-target OK")

if __name__ == "__main__": main()
