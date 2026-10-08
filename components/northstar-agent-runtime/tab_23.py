"""Jump game II (tab-23), tabulation DP."""
from __future__ import annotations
import ast
VERSION = "tab-jump2.v1"

def min_jumps(nums: list) -> int:
    n = len(nums)
    if n <= 1: return 0
    jumps = 0
    cur_end = 0
    cur_far = 0
    for i in range(n - 1):
        if i + nums[i] > cur_far: cur_far = i + nums[i]
        if i == cur_end:
            jumps += 1
            cur_end = cur_far
    return jumps

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
    assert min_jumps([2, 3, 1, 1, 4]) == 2
    assert min_jumps([2, 3, 0, 1, 4]) == 2
    assert min_jumps([1]) == 0
    assert stdlib_only()
    print("tab-jump2 OK")

if __name__ == "__main__": main()
