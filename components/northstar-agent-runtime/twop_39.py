"""min_subarray_len (two-pointer), minimal subarray length with sum >= target. IS: exact O(n) sliding-window minimum length for arrays of positive ints; returns 0 when no subarray qualifies. IS NOT: valid for non-positive elements; negatives break the sliding-window invariant."""
from __future__ import annotations

import ast

VERSION = "twop-39.v1"


def min_subarray_len(target: int, nums: list[int]) -> int:
    if isinstance(target, bool) or not isinstance(target, int) or target <= 0:
        raise ValueError("target must be a positive integer")
    if not isinstance(nums, list) or any(
        isinstance(x, bool) or not isinstance(x, int) or x <= 0 for x in nums
    ):
        raise ValueError("nums must be a list of positive integers")
    best = 0
    total = 0
    lo = 0
    for hi, x in enumerate(nums):
        total += x
        while total >= target:
            length = hi - lo + 1
            if best == 0 or length < best:
                best = length
            total -= nums[lo]
            lo += 1
    return best


def stdlib_only() -> bool:
    import pathlib

    allowed = {"__future__", "ast", "pathlib", "typing"}
    tree = ast.parse(pathlib.Path(__file__).read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if (node.module or "").split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    assert min_subarray_len(7, [2, 3, 1, 2, 4, 3]) == 2
    assert min_subarray_len(4, [1, 4, 4]) == 1
    assert min_subarray_len(11, [1, 2, 3, 4, 5]) == 3
    assert min_subarray_len(100, [1, 2, 3]) == 0  # edge: no qualifying subarray
    assert min_subarray_len(5, []) == 0
    try:
        min_subarray_len(7, [2, -1, 4])
    except ValueError:
        pass
    else:
        raise AssertionError("non-positive element must raise ValueError")
    try:
        min_subarray_len(0, [1, 2])
    except ValueError:
        pass
    else:
        raise AssertionError("non-positive target must raise ValueError")
    assert stdlib_only()
    print("twop_39 OK")


if __name__ == "__main__":
    main()
