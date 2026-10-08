"""Maximum Width Ramp (two-pointer), find the widest j - i with a[i] <= a[j]. IS: a decreasing-index stack plus a right-to-left pointer scan. IS NOT: a brute-force O(n^2) pair check."""

from __future__ import annotations

import ast

VERSION = "twop-09.v1"


def _check_nums(values: object, name: str) -> list[int | float]:
    if not isinstance(values, list):
        raise ValueError(f"{name} must be a list")
    for v in values:
        if isinstance(v, bool) or not isinstance(v, (int, float)):
            raise ValueError(
                f"{name} elements must be int or float, got {type(v).__name__}"
            )
    return list(values)


def max_width_ramp(nums: list[int | float]) -> int:
    """Return ``max(j - i)`` over all ``i < j`` with ``nums[i] <= nums[j]``.

    Runs in O(n): a stack holds indices of a strictly decreasing prefix,
    then a pointer sweeps ``j`` right-to-left, popping every index it can
    pair with. Fail-closed: ``nums`` must be a list of numbers, otherwise
    :class:`ValueError`. Fewer than 2 elements (edge) yields 0.
    """
    values = _check_nums(nums, "nums")
    n = len(values)
    if n < 2:
        return 0
    stack: list[int] = []
    for i, v in enumerate(values):
        if not stack or v < values[stack[-1]]:
            stack.append(i)
    best = 0
    for j in range(n - 1, -1, -1):
        while stack and values[stack[-1]] <= values[j]:
            width = j - stack.pop()
            if width > best:
                best = width
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
    assert max_width_ramp([6, 0, 8, 2, 1, 5]) == 4
    assert max_width_ramp([9, 8, 1, 0, 1, 9, 4, 0, 4, 1]) == 7
    assert max_width_ramp([5, 4, 3, 2, 1]) == 0
    assert max_width_ramp([]) == 0  # edge: empty list
    assert max_width_ramp([7]) == 0  # edge: single element
    assert max_width_ramp([1, 2, 3, 4]) == 3
    try:
        max_width_ramp([1, None, 3])  # type: ignore[list-item]
    except ValueError:
        pass
    else:
        raise AssertionError("non-number element must raise ValueError")
    assert stdlib_only()
    print("twop_09 OK")


if __name__ == "__main__":
    main()
