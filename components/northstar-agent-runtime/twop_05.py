"""Three Sum Smaller (two-pointer), count the triplets whose sum is below the target. IS: a fix-one-index plus two-pointer scan counting (hi - lo) runs at once. IS NOT: a brute-force O(n^3) counter."""

from __future__ import annotations

import ast

VERSION = "twop-05.v1"


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


def three_sum_smaller(nums: list[int | float], target: int | float) -> int:
    """Count triplets ``i < j < k`` with ``nums[i] + nums[j] + nums[k] < target``.

    Fail-closed: ``nums`` must be a list of numbers and ``target`` a number,
    otherwise :class:`ValueError`.
    """
    values = sorted(_check_nums(nums, "nums"))
    target = _check_target(target)
    count = 0
    n = len(values)
    for i in range(n - 2):
        lo, hi = i + 1, n - 1
        while lo < hi:
            if values[i] + values[lo] + values[hi] < target:
                count += hi - lo
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
    assert three_sum_smaller([-2, 0, 1, 3], 2) == 2
    assert three_sum_smaller([0, 0, 0], 1) == 1
    assert three_sum_smaller([1, 2, 3], 0) == 0
    assert three_sum_smaller([], 5) == 0  # edge: empty list
    assert three_sum_smaller([1, 2], 10) == 0  # edge: fewer than 3 elements
    try:
        three_sum_smaller("123", 2)  # type: ignore[arg-type]
    except ValueError:
        pass
    else:
        raise AssertionError("non-list input must raise ValueError")
    assert stdlib_only()
    print("twop_05 OK")


if __name__ == "__main__":
    main()
