"""squares_of_sorted_array (two-pointer), sorted squares of a sorted array. IS: O(n) two-ended merge of squares of a non-decreasing array. IS NOT: a square-then-sort."""
from __future__ import annotations
import ast

VERSION = "twop-19.v1"

def squares_of_sorted_array(nums: list[int]) -> list[int]:
    """Return the squares of sorted nums in non-decreasing order."""
    if not isinstance(nums, list):
        raise ValueError("nums must be a list")
    n = len(nums)
    out = [0] * n
    lo = 0
    hi = n - 1
    for write in range(n - 1, -1, -1):
        if abs(nums[lo]) > abs(nums[hi]):
            out[write] = nums[lo] * nums[lo]
            lo += 1
        else:
            out[write] = nums[hi] * nums[hi]
            hi -= 1
    return out

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
    assert squares_of_sorted_array([-4, -1, 0, 3, 10]) == [0, 1, 9, 16, 100]
    assert squares_of_sorted_array([]) == []
    assert squares_of_sorted_array([-7, -3, 2, 3, 11]) == [4, 9, 9, 49, 121]
    assert stdlib_only()
    print("squares_of_sorted_array OK")

if __name__ == "__main__":
    main()
