"""Strict 2D Rectangle Difference: difference array example.

A strict 2D difference array: zero-value updates and out-of-bounds rectangles are rejected fail-closed; materialize() returns the grid.

What this IS: a real strict 2D difference array with materialization, fail-closed on zero updates
What this IS NOT: a permissive variant that silently accepts bad input
"""

from __future__ import annotations

import ast

#: Module version.
DIFF_31_VERSION = "strict-rect-diff.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.diff-strict-rect-diff.v1"


class DiffError(Exception):
    """Fail-closed."""


class StrictRectDiff:
    """Strict 2D difference array."""

    def __init__(self, rows: int, cols: int):
        if rows <= 0 or cols <= 0:
            raise DiffError("rows and cols must be > 0")
        self.rows = rows
        self.cols = cols
        self._d = [[0] * (cols + 1) for _ in range(rows + 1)]

    def add(self, r1: int, c1: int, r2: int, c2: int, v: int) -> None:
        if v == 0:
            raise DiffError("zero updates rejected")
        if not (0 <= r1 <= r2 < self.rows and 0 <= c1 <= c2 < self.cols):
            raise DiffError("rectangle out of bounds")
        d = self._d
        d[r1][c1] += v
        d[r1][c2 + 1] -= v
        d[r2 + 1][c1] -= v
        d[r2 + 1][c2 + 1] += v

    def query(self, r: int, c: int) -> int:
        if not (0 <= r < self.rows and 0 <= c < self.cols):
            raise DiffError("cell out of bounds")
        total = 0
        for i in range(r + 1):
            row = self._d[i]
            for j in range(c + 1):
                total += row[j]
        return total

    def materialize(self) -> list:
        grid = [[0] * self.cols for _ in range(self.rows)]
        for i in range(self.rows):
            for j in range(self.cols):
                v = self._d[i][j]
                if i > 0:
                    v += grid[i - 1][j]
                if j > 0:
                    v += grid[i][j - 1]
                if i > 0 and j > 0:
                    v -= grid[i - 1][j - 1]
                grid[i][j] = v
        return grid

def test_basic():
    s = StrictRectDiff(2, 2)
    s.add(0, 0, 1, 1, 3)
    assert s.query(1, 1) == 3
    assert s.materialize() == [[3, 3], [3, 3]]


def test_zero_rejected():
    s = StrictRectDiff(2, 2)
    try:
        s.add(0, 0, 1, 1, 0)
    except DiffError:
        return
    raise AssertionError("expected DiffError")


def test_oob_rejected():
    s = StrictRectDiff(2, 2)
    try:
        s.add(1, 1, 2, 2, 1)
    except DiffError:
        return
    raise AssertionError("expected DiffError")


def test_bad_cell():
    s = StrictRectDiff(2, 2)
    try:
        s.query(2, 0)
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
    test_zero_rejected()
    test_oob_rejected()
    test_bad_cell()
    assert stdlib_only()
    print("diff-31 OK: strict-rect-diff")


if __name__ == "__main__":
    main()
