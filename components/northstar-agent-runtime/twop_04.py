"""Three Sum Closest (two-pointer), find the triplet sum nearest to the target. IS: a fix-one-index plus two-pointer scan tracking the best sum seen. IS NOT: an exhaustive triplet enumeration."""

from __future__ import annotations

import ast

VERSION = "twop-04.v1"


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


def three_sum_closest(
    nums: list[int | float], target: int | float
) -> int | float:
    """Return the sum of the triplet closest to ``target``.

    Fail-closed: ``nums`` must hold at least 3 numbers and ``target`` must
    be a number, otherwise :class:`ValueError`.
    """
    values = sorted(_check_nums(nums, "nums"))
    target = _check_target(target)
    if len(values) < 3:
        raise ValueError("nums must contain at least 3 elements")
    best = values[0] + values[1] + values[2]
    n = len(values)
    for i in range(n - 2):
        lo, hi = i + 1, n - 1
        while lo < hi:
            s = values[i] + values[lo] + values[hi]
            if abs(s - target) < abs(best - target):
                best = s
            if s < target:
                lo += 1
            elif s > target:
                hi -= 1
            else:
                return s
    return best


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
    assert three_sum_closest([-1, 2, 1, -4], 1) == 2
    assert three_sum_closest([0, 0, 0], 1) == 0
    assert three_sum_closest([1, 1, 1, 0], -100) == 2
    assert three_sum_closest([1, 2, 3], 10) == 6  # edge: exactly 3 elements
    try:
        three_sum_closest([1, 2], 3)
    except ValueError:
        pass
    else:
        raise AssertionError("fewer than 3 elements must raise ValueError")
    assert stdlib_only()
    print("twop_04 OK")


if __name__ == "__main__":
    main()
