"""Four Sum (two-pointer), find all unique quadruplets that sum to the target. IS: a fix-two-indices plus two-pointer scan with duplicate skipping. IS NOT: a brute-force O(n^4) enumeration."""

from __future__ import annotations

import ast

VERSION = "twop-06.v1"


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


def four_sum(
    nums: list[int | float], target: int | float
) -> list[tuple[int | float, ...]]:
    """Return all unique quadruplets ``(a, b, c, d)`` summing to ``target``.

    The input is sorted internally; quadruplets come out in sorted order.
    Fail-closed: ``nums`` must be a list of numbers and ``target`` a number,
    otherwise :class:`ValueError`.
    """
    values = sorted(_check_nums(nums, "nums"))
    target = _check_target(target)
    out: list[tuple[int | float, ...]] = []
    n = len(values)
    for i in range(n - 3):
        if i > 0 and values[i] == values[i - 1]:
            continue
        for j in range(i + 1, n - 2):
            if j > i + 1 and values[j] == values[j - 1]:
                continue
            lo, hi = j + 1, n - 1
            while lo < hi:
                s = values[i] + values[j] + values[lo] + values[hi]
                if s == target:
                    out.append((values[i], values[j], values[lo], values[hi]))
                    lo += 1
                    hi -= 1
                    while lo < hi and values[lo] == values[lo - 1]:
                        lo += 1
                    while lo < hi and values[hi] == values[hi + 1]:
                        hi -= 1
                elif s < target:
                    lo += 1
                else:
                    hi -= 1
    return out


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
    assert four_sum([1, 0, -1, 0, -2, 2], 0) == [
        (-2, -1, 1, 2),
        (-2, 0, 0, 2),
        (-1, 0, 0, 1),
    ]
    assert four_sum([2, 2, 2, 2, 2], 8) == [(2, 2, 2, 2)]
    assert four_sum([1, 2, 3], 100) == []
    assert four_sum([], 0) == []  # edge: empty list
    try:
        four_sum([1, 2, 3, 4], "0")  # type: ignore[arg-type]
    except ValueError:
        pass
    else:
        raise AssertionError("non-number target must raise ValueError")
    assert stdlib_only()
    print("twop_06 OK")


if __name__ == "__main__":
    main()
