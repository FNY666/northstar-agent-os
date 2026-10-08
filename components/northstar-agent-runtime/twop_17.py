"""partition_by_pivot (two-pointer), rearrange a list around a pivot value in place. IS: in-place partition with <pivot before >=pivot, returns pivot position. IS NOT: a full sort or a stable partition."""
from __future__ import annotations
import ast

VERSION = "twop-17.v1"

def partition_by_pivot(nums: list[int], pivot: int) -> int:
    """Partition nums around pivot: <pivot first, then >=pivot; return split index."""
    if not isinstance(nums, list):
        raise ValueError("nums must be a list")
    if not isinstance(pivot, int):
        raise ValueError("pivot must be an int")
    lo = 0
    hi = len(nums) - 1
    while lo <= hi:
        if nums[lo] < pivot:
            lo += 1
        elif nums[hi] >= pivot:
            hi -= 1
        else:
            nums[lo], nums[hi] = nums[hi], nums[lo]
            lo += 1
            hi -= 1
    return lo

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
    a = [9, 12, 3, 5, 14, 10, 10]
    k = partition_by_pivot(a, 10)
    assert all(x < 10 for x in a[:k]) and all(x >= 10 for x in a[k:]), (k, a)
    b = [1, 2, 3]
    k2 = partition_by_pivot(b, 5)
    assert k2 == 3, (k2, b)
    c = [7, 7, 7]
    k3 = partition_by_pivot(c, 7)
    assert k3 == 0, (k3, c)
    assert stdlib_only()
    print("partition_by_pivot OK")

if __name__ == "__main__":
    main()
