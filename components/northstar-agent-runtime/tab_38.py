"""Maximum product subarray (tab-38), tabulation DP."""
from __future__ import annotations
import ast
VERSION = "tab-maxprod.v1"

def max_product(nums: list) -> int:
    best = cur_max = cur_min = nums[0]
    for x in nums[1:]:
        cand = (x, cur_max * x, cur_min * x)
        cur_max = max(cand)
        cur_min = min(cand)
        if cur_max > best: best = cur_max
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
    assert max_product([2, 3, -2, 4]) == 6
    assert max_product([-2, 0, -1]) == 0
    assert max_product([-2, 3, -4]) == 24
    assert stdlib_only()
    print("tab-maxprod OK")

if __name__ == "__main__": main()
