"""Maximum subarray (tab-37), tabulation DP."""
from __future__ import annotations
import ast
VERSION = "tab-maxsub.v1"

def max_subarray(nums: list) -> int:
    best = cur = nums[0]
    for x in nums[1:]:
        cur = x if cur + x < x else cur + x
        if cur > best: best = cur
    return best

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
    assert max_subarray([-2, 1, -3, 4, -1, 2, 1, -5, 4]) == 6
    assert max_subarray([1]) == 1
    assert max_subarray([-1]) == -1
    assert stdlib_only()
    print("tab-maxsub OK")

if __name__ == "__main__": main()
