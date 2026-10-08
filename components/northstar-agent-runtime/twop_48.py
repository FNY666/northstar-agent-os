"""closest_pair_sum (two-pointer), pair sum closest to target in a sorted list. IS: converging pointers finding the pair whose sum minimizes |sum-target|, returning the pair and its sum. IS NOT: a promise of a unique answer when several pairs tie (first found wins)."""
from __future__ import annotations

import ast

VERSION = "twop-48.v1"


def _is_number(v: object) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def closest_pair_sum(
    nums: list[int] | list[float], target: int | float
) -> tuple[tuple[int | float, int | float], int | float]:
    """Return ((a, b), s): the pair in sorted nums with sum s closest to target."""
    if not isinstance(nums, list):
        raise ValueError("nums must be a list")
    if len(nums) < 2:
        raise ValueError("nums must contain at least two elements")
    for v in nums:
        if not _is_number(v):
            raise ValueError("nums must contain only numbers")
    if not _is_number(target):
        raise ValueError("target must be a number")
    if any(nums[i] > nums[i + 1] for i in range(len(nums) - 1)):
        raise ValueError("nums must be sorted in non-decreasing order")
    left = 0
    right = len(nums) - 1
    best_a = nums[left]
    best_b = nums[right]
    best_sum = best_a + best_b
    while left < right:
        s = nums[left] + nums[right]
        if abs(s - target) < abs(best_sum - target):
            best_a, best_b, best_sum = nums[left], nums[right], s
        if s == target:
            break
        if s < target:
            left += 1
        else:
            right -= 1
    return (best_a, best_b), best_sum


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
    pair, s = closest_pair_sum([1, 2, 3, 4, 5], 10)
    assert s == 9 and pair == (4, 5), (pair, s)
    pair, s = closest_pair_sum([10, 22, 28, 29, 30, 40], 54)
    assert s == 52 and pair == (22, 30), (pair, s)
    pair, s = closest_pair_sum([-5, -1, 3, 8], 2)
    assert s == 2 and pair == (-1, 3), (pair, s)  # edge: exact match
    pair, s = closest_pair_sum([1, 2], 100)
    assert s == 3 and pair == (1, 2), (pair, s)
    try:
        closest_pair_sum([5, 1, 3], 6)
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for unsorted input")
    try:
        closest_pair_sum([1], 2)
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for single-element list")
    assert stdlib_only()
    print("closest_pair_sum OK")


if __name__ == "__main__":
    main()
