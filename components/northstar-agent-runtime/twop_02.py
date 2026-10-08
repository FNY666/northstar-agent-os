"""Pair Sum Count (two-pointer), count the pairs in a sorted list that sum to the target in O(n). IS: a single two-pointer pass that multiplies duplicate-run counts. IS NOT: a nested-loop or hash-map counter."""

from __future__ import annotations

import ast

VERSION = "twop-02.v1"


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


def pair_sum_count(nums: list[int | float], target: int | float) -> int:
    """Count pairs ``i < j`` with ``nums[i] + nums[j] == target`` in O(n).

    Fail-closed: ``nums`` must be an ascending-sorted list of numbers and
    ``target`` a number, otherwise :class:`ValueError`.
    """
    values = _check_nums(nums, "nums")
    target = _check_target(target)
    if any(values[i] > values[i + 1] for i in range(len(values) - 1)):
        raise ValueError("nums must be sorted in ascending order")
    count = 0
    lo, hi = 0, len(values) - 1
    while lo < hi:
        s = values[lo] + values[hi]
        if s == target:
            if values[lo] == values[hi]:
                n = hi - lo + 1
                count += n * (n - 1) // 2
                break
            left_val, right_val = values[lo], values[hi]
            left_run = 0
            while lo <= hi and values[lo] == left_val:
                left_run += 1
                lo += 1
            right_run = 0
            while hi >= lo and values[hi] == right_val:
                right_run += 1
                hi -= 1
            count += left_run * right_run
        elif s < target:
            lo += 1
        else:
            hi -= 1
    return count


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
    assert pair_sum_count([1, 2, 3, 4, 5], 6) == 2
    assert pair_sum_count([1, 1, 1, 1], 2) == 6
    assert pair_sum_count([1, 2, 3], 10) == 0
    assert pair_sum_count([], 5) == 0  # edge: empty list
    assert pair_sum_count([1, 1, 2, 2, 3, 3], 4) == 5  # 2*2 + C(2,2)
    try:
        pair_sum_count([2, 1, 3], 3)
    except ValueError:
        pass
    else:
        raise AssertionError("unsorted input must raise ValueError")
    assert stdlib_only()
    print("twop_02 OK")


if __name__ == "__main__":
    main()
