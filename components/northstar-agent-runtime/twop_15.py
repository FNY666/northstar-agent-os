"""sort_colors (two-pointer), sort a 0/1/2 list in place with three pointers. IS: one-pass Dutch-national-flag partition of 0s, 1s, 2s. IS NOT: a general counting sort."""
from __future__ import annotations
import ast

VERSION = "twop-15.v1"

def sort_colors(nums: list[int]) -> None:
    """Sort nums of 0s, 1s, 2s in place with low/mid/high pointers."""
    if not isinstance(nums, list):
        raise ValueError("nums must be a list")
    if any(x not in (0, 1, 2) for x in nums):
        raise ValueError("nums may only contain 0, 1, 2")
    low = 0
    mid = 0
    high = len(nums) - 1
    while mid <= high:
        if nums[mid] == 0:
            nums[low], nums[mid] = nums[mid], nums[low]
            low += 1
            mid += 1
        elif nums[mid] == 1:
            mid += 1
        else:
            nums[mid], nums[high] = nums[high], nums[mid]
            high -= 1

def stdlib_only() -> bool:
    """AST-parse this file; return False if any import outside the allowed set appears."""
    import pathlib
    src = pathlib.Path(__file__).read_text()
    allowed = {"__future__", "ast", "pathlib", "typing"}
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if (node.module or "").split(".")[0] not in allowed:
                return False
    return True

def main() -> None:
    a = [2, 0, 2, 1, 1, 0]
    sort_colors(a)
    assert a == [0, 0, 1, 1, 2, 2], a
    b = [2, 1, 0]
    sort_colors(b)
    assert b == [0, 1, 2], b
    c: list[int] = []
    sort_colors(c)
    assert c == []
    assert stdlib_only()
    print("sort_colors OK")

if __name__ == "__main__":
    main()
