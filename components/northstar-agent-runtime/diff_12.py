"""Batched Range Add Over Many Arrays: difference array example.

One update list applied to many same-length arrays: a single difference array computes the delta once, then each array is shifted by it.

What this IS: a real shared-delta batch update, fail-closed on length mismatch
What this IS NOT: applying the updates separately per array
"""

from __future__ import annotations

import ast

#: Module version.
DIFF_12_VERSION = "batch-range-add-multi.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.diff-batch-range-add-multi.v1"


class DiffError(Exception):
    """Fail-closed."""


def batch_range_add(arrays: list, updates: list) -> list:
    """Apply updates to every array; returns new lists."""
    if not arrays:
        raise DiffError("need at least one array")
    n = len(arrays[0])
    if any(len(a) != n for a in arrays):
        raise DiffError("all arrays must share one length")
    diff = [0] * (n + 1)
    for l, r, v in updates:
        if not (0 <= l <= r < n):
            raise DiffError("bad update")
        diff[l] += v
        diff[r + 1] -= v
    delta = []
    cur = 0
    for i in range(n):
        cur += diff[i]
        delta.append(cur)
    return [[a[i] + delta[i] for i in range(n)] for a in arrays]

def test_basic():
    assert batch_range_add([[1, 2, 3], [0, 0, 0]], [(0, 1, 10)]) == [[11, 12, 3], [10, 10, 0]]


def test_no_updates():
    assert batch_range_add([[5, 6]], []) == [[5, 6]]


def test_empty_arrays():
    try:
        batch_range_add([], [(0, 0, 1)])
    except DiffError:
        return
    raise AssertionError("expected DiffError")


def test_mismatch():
    try:
        batch_range_add([[1, 2], [1]], [(0, 0, 1)])
    except DiffError:
        return
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
    test_basic()
    test_no_updates()
    test_empty_arrays()
    test_mismatch()
    assert stdlib_only()
    print("diff-12 OK: batch-range-add-multi")


if __name__ == "__main__":
    main()
