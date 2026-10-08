"""two_sum_less_than_k (two-pointer), max pair sum below k in an unsorted list. IS: sort the list then use converging pointers to find the largest pair sum strictly less than k (-1 if none). IS NOT: a hash-map two-sum or a solver for sums >= k."""
from __future__ import annotations

import ast

VERSION = "twop-46.v1"


def _is_number(v: object) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def two_sum_less_than_k(nums: list[int] | list[float], k: int | float) -> int | float:
    """Return the largest pair sum of nums that is strictly less than k, or -1."""
    if not isinstance(nums, list):
        raise ValueError("nums must be a list")
    if len(nums) < 2:
        raise ValueError("nums must contain at least two elements")
    for v in nums:
        if not _is_number(v):
            raise ValueError("nums must contain only numbers")
    if not _is_number(k):
        raise ValueError("k must be a number")
    ordered = sorted(nums)
    left = 0
    right = len(ordered) - 1
    best: int | float | None = None
    while left < right:
        s = ordered[left] + ordered[right]
        if s < k:
            if best is None or s > best:
                best = s
            left += 1
        else:
            right -= 1
    return -1 if best is None else best


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
    assert two_sum_less_than_k([34, 23, 1, 24, 75, 33, 54, 8], 60) == 58
    assert two_sum_less_than_k([10, 20, 30], 15) == -1
    assert two_sum_less_than_k([5, 5, 5], 11) == 10  # edge: equal elements
    assert two_sum_less_than_k([-1, -2, -3, 4], 0) == -3
    assert two_sum_less_than_k([1, 2], 3) == -1  # edge: only pair reaches k
    try:
        two_sum_less_than_k([1], 5)
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for single-element list")
    try:
        two_sum_less_than_k([1, "x"], 5)
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for non-numeric element")
    assert stdlib_only()
    print("two_sum_less_than_k OK")


if __name__ == "__main__":
    main()
