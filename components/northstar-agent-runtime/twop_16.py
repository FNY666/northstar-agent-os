"""partition_by_parity (two-pointer), move evens before odds in place. IS: in-place two-ended parity partition. IS NOT: a stable sort or order-preserving filter."""
from __future__ import annotations
import ast

VERSION = "twop-16.v1"

def partition_by_parity(nums: list[int]) -> None:
    """Move all evens to the front of nums and odds to the back, in place."""
    if not isinstance(nums, list):
        raise ValueError("nums must be a list")
    lo = 0
    hi = len(nums) - 1
    while lo < hi:
        if nums[lo] % 2 == 0:
            lo += 1
        elif nums[hi] % 2 == 1:
            hi -= 1
        else:
            nums[lo], nums[hi] = nums[hi], nums[lo]
            lo += 1
            hi -= 1

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
    a = [3, 1, 2, 4]
    partition_by_parity(a)
    assert all(x % 2 == 0 for x in a[:2]) and all(x % 2 == 1 for x in a[2:]), a
    b = [0]
    partition_by_parity(b)
    assert b == [0], b
    c: list[int] = []
    partition_by_parity(c)
    assert c == []
    assert stdlib_only()
    print("partition_by_parity OK")

if __name__ == "__main__":
    main()
