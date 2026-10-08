"""Range Add Range Sum: difference array example.

Range adds via a difference array, then prefix sums; range sums are answered from the materialized array.

What this IS: real range-add/range-sum via difference array plus prefix sums, fail-closed on bad bounds
What this IS NOT: a lazy segment tree; this materializes the array once
"""

from __future__ import annotations

import ast

#: Module version.
DIFF_02_VERSION = "range-add-range-sum.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.diff-range-add-range-sum.v1"


class DiffError(Exception):
    """Fail-closed."""


def apply_updates(n: int, updates: list) -> list:
    """updates: list of (l, r, v). Returns the final array."""
    diff = [0] * (n + 1)
    for l, r, v in updates:
        if not (0 <= l <= r < n):
            raise DiffError("bounds must satisfy 0 <= l <= r < n")
        diff[l] += v
        diff[r + 1] -= v
    out = []
    cur = 0
    for i in range(n):
        cur += diff[i]
        out.append(cur)
    return out


def range_sum(arr: list, l: int, r: int) -> int:
    if not (0 <= l <= r < len(arr)):
        raise DiffError("bounds must satisfy 0 <= l <= r < len(arr)")
    return sum(arr[l:r + 1])

def test_apply():
    assert apply_updates(5, [(0, 2, 3), (1, 4, -2)]) == [3, 1, 1, -2, -2]


def test_range_sum():
    arr = apply_updates(5, [(0, 2, 3), (1, 4, -2)])
    assert range_sum(arr, 1, 3) == 0
    assert range_sum(arr, 0, 4) == 1


def test_empty_updates():
    assert apply_updates(3, []) == [0, 0, 0]


def test_bad():
    for bad in (lambda: apply_updates(3, [(0, 3, 1)]),
                lambda: range_sum([1, 2], 1, 0)):
        try:
            bad()
        except DiffError:
            continue
        raise AssertionError("expected DiffError")

def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    """Self-check."""
    test_apply()
    test_range_sum()
    test_empty_updates()
    test_bad()
    assert stdlib_only()
    print("diff-02 OK: range-add-range-sum")


if __name__ == "__main__":
    main()
