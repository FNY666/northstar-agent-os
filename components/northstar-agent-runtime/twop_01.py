"""Two Sum Sorted (two-pointer), find the 1-based index pair in a sorted list that sums to the target. IS: a classic left/right two-pointer scan over an ascending-sorted list. IS NOT: a hash-map two-sum for unsorted input."""

from __future__ import annotations

import ast

VERSION = "twop-01.v1"


def _check_nums(values: object, name: str) -> list[int | float]:
    if not isinstance(values, list):
        raise ValueError(f"{name} must be a list")
    for v in values:
        if isinstance(v, bool) or not isinstance(v, (int, float)):
            raise ValueError(
                f"{name} elements must be int or float, got {type(v).__name__}"
            )
    return list(values)


def _check_target(target: object) -> int | float:
    if isinstance(target, bool) or not isinstance(target, (int, float)):
        raise ValueError("target must be a number")
    return target


def two_sum_sorted(
    nums: list[int | float], target: int | float
) -> tuple[int, int] | None:
    """Return the 1-based index pair ``(i, j)`` with ``nums[i-1] + nums[j-1] == target``.

    Fail-closed: ``nums`` must be an ascending-sorted list of numbers and
    ``target`` a number, otherwise :class:`ValueError`.
    """
    values = _check_nums(nums, "nums")
    target = _check_target(target)
    if any(values[i] > values[i + 1] for i in range(len(values) - 1)):
        raise ValueError("nums must be sorted in ascending order")
    lo, hi = 0, len(values) - 1
    while lo < hi:
        s = values[lo] + values[hi]
        if s == target:
            return (lo + 1, hi + 1)
        if s < target:
            lo += 1
        else:
            hi -= 1
    return None


def stdlib_only() -> bool:
    """AST-check: no imports outside the allowed stdlib set."""
    import pathlib

    allowed = {"__future__", "ast", "pathlib", "typing"}
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"))
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
    assert two_sum_sorted([2, 7, 11, 15], 9) == (1, 2)
    assert two_sum_sorted([2, 7, 11, 15], 10) is None
    assert two_sum_sorted([], 1) is None  # edge: empty list
    assert two_sum_sorted([5], 5) is None  # edge: single element
    assert two_sum_sorted([-3, -1, 0, 4, 9], 1) == (1, 4)
    try:
        two_sum_sorted([3, 1, 2], 4)
    except ValueError:
        pass
    else:
        raise AssertionError("unsorted input must raise ValueError")
    assert stdlib_only()
    print("twop_01 OK")


if __name__ == "__main__":
    main()
