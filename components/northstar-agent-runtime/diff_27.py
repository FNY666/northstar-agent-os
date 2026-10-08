"""2D Rectangle Add Rectangle Sum: difference array example.

2D difference array materialized into a full grid; rectangle sums are answered from the materialized grid.

What this IS: a real 2D difference array with materialization, fail-closed on bad input
What this IS NOT: a 2D BIT
"""

from __future__ import annotations

import ast

#: Module version.
DIFF_27_VERSION = "rect-add-rect-sum-2d.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.diff-rect-add-rect-sum-2d.v1"


class DiffError(Exception):
    """Fail-closed."""


class RectAddRectSum:
    """2D difference array: rectangle add, rectangle sum query."""

    def __init__(self, rows: int, cols: int):
        if rows <= 0 or cols <= 0:
            raise DiffError("rows and cols must be > 0")
        self.rows = rows
        self.cols = cols
        self._d = [[0] * (cols + 1) for _ in range(rows + 1)]
        self._grid = None

    def add(self, r1: int, c1: int, r2: int, c2: int, v: int) -> None:
        if not (0 <= r1 <= r2 < self.rows and 0 <= c1 <= c2 < self.cols):
            raise DiffError("bad rectangle")
        d = self._d
        d[r1][c1] += v
        d[r1][c2 + 1] -= v
        d[r2 + 1][c1] -= v
        d[r2 + 1][c2 + 1] += v
        self._grid = None

    def _build(self) -> list:
        if self._grid is None:
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
            self._grid = grid
        return self._grid

    def rect_sum(self, r1: int, c1: int, r2: int, c2: int) -> int:
        if not (0 <= r1 <= r2 < self.rows and 0 <= c1 <= c2 < self.cols):
            raise DiffError("bad rectangle")
        g = self._build()
        total = 0
        for i in range(r1, r2 + 1):
            total += sum(g[i][c1:c2 + 1])
        return total

def test_basic():
    q = RectAddRectSum(3, 3)
    q.add(0, 0, 1, 1, 2)
    assert q.rect_sum(0, 0, 2, 2) == 8
    assert q.rect_sum(0, 0, 0, 0) == 2
    assert q.rect_sum(2, 2, 2, 2) == 0


def test_two_rects():
    q = RectAddRectSum(3, 3)
    q.add(0, 0, 1, 1, 2)
    q.add(2, 2, 2, 2, 5)
    assert q.rect_sum(0, 0, 2, 2) == 13


def test_no_adds():
    q = RectAddRectSum(2, 2)
    assert q.rect_sum(0, 0, 1, 1) == 0


def test_bad():
    q = RectAddRectSum(2, 2)
    try:
        q.rect_sum(0, 0, 2, 2)
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
    test_two_rects()
    test_no_adds()
    test_bad()
    assert stdlib_only()
    print("diff-27 OK: rect-add-rect-sum-2d")


if __name__ == "__main__":
    main()
