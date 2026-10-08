"""Three Sum (two-pointer), find all unique triplets that sum to zero. IS: a fix-one-index plus two-pointer scan with duplicate skipping. IS NOT: a brute-force O(n^3) enumeration."""

from __future__ import annotations

import ast

VERSION = "twop-03.v1"


def _check_nums(values: object, name: str) -> list[int | float]:
    if not isinstance(values, list):
        raise ValueError(f"{name} must be a list")
    for v in values:
        if isinstance(v, bool) or not isinstance(v, (int, float)):
            raise ValueError(
                f"{name} elements must be int or float, got {type(v).__name__}"
            )
    return list(values)


def three_sum(nums: list[int | float]) -> list[tuple[int | float, ...]]:
    """Return all unique triplets ``(a, b, c)`` with ``a + b + c == 0``.

    The input is sorted internally; triplets come out in sorted order.
    Fail-closed: ``nums`` must be a list of numbers, else :class:`ValueError`.
    """
    values = sorted(_check_nums(nums, "nums"))
    out: list[tuple[int | float, ...]] = []
    n = len(values)
    for i in range(n - 2):
        if i > 0 and values[i] == values[i - 1]:
            continue
        lo, hi = i + 1, n - 1
        while lo < hi:
            s = values[i] + values[lo] + values[hi]
            if s == 0:
                out.append((values[i], values[lo], values[hi]))
                lo += 1
                hi -= 1
                while lo < hi and values[lo] == values[lo - 1]:
                    lo += 1
                while lo < hi and values[hi] == values[hi + 1]:
                    hi -= 1
            elif s < 0:
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
    assert three_sum([-1, 0, 1, 2, -1, -4]) == [(-1, -1, 2), (-1, 0, 1)]
    assert three_sum([0, 1, 1]) == []
    assert three_sum([0, 0, 0]) == [(0, 0, 0)]
    assert three_sum([]) == []  # edge: empty list
    assert three_sum([1, 2]) == []  # edge: fewer than 3 elements
    try:
        three_sum([1, "x", 3])  # type: ignore[list-item]
    except ValueError:
        pass
    else:
        raise AssertionError("non-number element must raise ValueError")
    assert stdlib_only()
    print("twop_03 OK")


if __name__ == "__main__":
    main()
