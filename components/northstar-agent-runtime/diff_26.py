"""2D Rectangle Add Point Query: difference array example.

2D difference array: add v to every cell of rectangle [r1..r2]x[c1..c2]; point queries via 2D prefix sums.

What this IS: a real 2D difference array, fail-closed on bad rectangles
What this IS NOT: updating every cell of each rectangle
"""

from __future__ import annotations

import ast

#: Module version.
DIFF_26_VERSION = "rect-add-point-query-2d.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.diff-rect-add-point-query-2d.v1"


class DiffError(Exception):
    """Fail-closed."""


class RectAddPointQuery:
    """2D difference array: rectangle add, point query."""

    def __init__(self, rows: int, cols: int):
        if rows <= 0 or cols <= 0:
            raise DiffError("rows and cols must be > 0")
        self.rows = rows
        self.cols = cols
        self._d = [[0] * (cols + 1) for _ in range(rows + 1)]

    def add(self, r1: int, c1: int, r2: int, c2: int, v: int) -> None:
        if not (0 <= r1 <= r2 < self.rows and 0 <= c1 <= c2 < self.cols):
            raise DiffError("bad rectangle")
        d = self._d
        d[r1][c1] += v
        d[r1][c2 + 1] -= v
        d[r2 + 1][c1] -= v
        d[r2 + 1][c2 + 1] += v

    def query(self, r: int, c: int) -> int:
        if not (0 <= r < self.rows and 0 <= c < self.cols):
            raise DiffError("bad cell")
        total = 0
        for i in range(r + 1):
            row = self._d[i]
            for j in range(c + 1):
                total += row[j]
        return total

def test_basic():
    q = RectAddPointQuery(3, 3)
    q.add(0, 0, 1, 1, 5)
    assert q.query(0, 0) == 5
    assert q.query(1, 1) == 5
    assert q.query(2, 2) == 0
    assert q.query(0, 2) == 0


def test_overlap():
    q = RectAddPointQuery(3, 3)
    q.add(0, 0, 1, 1, 5)
    q.add(1, 1, 2, 2, 3)
    assert q.query(1, 1) == 8
    assert q.query(2, 2) == 3


def test_single_cell():
    q = RectAddPointQuery(2, 2)
    q.add(1, 0, 1, 0, 7)
    assert q.query(1, 0) == 7
    assert q.query(0, 0) == 0


def test_bad():
    q = RectAddPointQuery(2, 2)
    try:
        q.add(0, 0, 2, 2, 1)
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
    test_overlap()
    test_single_cell()
    test_bad()
    assert stdlib_only()
    print("diff-26 OK: rect-add-point-query-2d")


if __name__ == "__main__":
    main()
