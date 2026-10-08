"""longest_ones_with_k_flips (two-pointer), longest subarray of 1s flipping at most k zeros. IS: exact O(n) sliding-window maximum length over binary lists with at most k zero flips. IS NOT: a counter of total ones; the answer must be a contiguous subarray."""
from __future__ import annotations

import ast

VERSION = "twop-40.v1"


def longest_ones_with_k_flips(nums: list[int], k: int) -> int:
    if not isinstance(nums, list) or any(x not in (0, 1) for x in nums):
        raise ValueError("nums must be a list of 0s and 1s")
    if isinstance(k, bool) or not isinstance(k, int) or k < 0:
        raise ValueError("k must be a non-negative integer")
    best = 0
    zeros = 0
    lo = 0
    for hi, x in enumerate(nums):
        if x == 0:
            zeros += 1
        while zeros > k:
            if nums[lo] == 0:
                zeros -= 1
            lo += 1
        length = hi - lo + 1
        if length > best:
            best = length
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
    assert longest_ones_with_k_flips([1, 1, 1, 0, 0, 0, 1, 1, 1, 1, 0], 2) == 6
    assert longest_ones_with_k_flips([1, 1, 1, 1], 0) == 4
    assert longest_ones_with_k_flips([0, 0, 0], 1) == 1
    assert longest_ones_with_k_flips([], 2) == 0  # edge: empty list
    assert longest_ones_with_k_flips([0, 1, 0], 5) == 3
    try:
        longest_ones_with_k_flips([1, 2, 1], 1)
    except ValueError:
        pass
    else:
        raise AssertionError("non-binary nums must raise ValueError")
    try:
        longest_ones_with_k_flips([1, 0], -1)
    except ValueError:
        pass
    else:
        raise AssertionError("negative k must raise ValueError")
    assert stdlib_only()
    print("twop_40 OK")


if __name__ == "__main__":
    main()
