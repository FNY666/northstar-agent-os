"""Covered Cells After Rectangle Adds: difference array example.

2D difference array; count cells whose final value is positive after all positive rectangle additions.

What this IS: a real 2D covered-cell count, fail-closed on non-positive values
What this IS NOT: counting without the difference array
"""

from __future__ import annotations

import ast

#: Module version.
DIFF_49_VERSION = "rect-add-covered-count.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.diff-rect-add-covered-count.v1"


class DiffError(Exception):
    """Fail-closed."""


def covered_cells(rows: int, cols: int, rects: list) -> int:
    """rects: list of (r1, c1, r2, c2, v) with v > 0. Counts cells with value > 0."""
    if rows <= 0 or cols <= 0:
        raise DiffError("rows and cols must be > 0")
    d = [[0] * (cols + 1) for _ in range(rows + 1)]
    for r1, c1, r2, c2, v in rects:
        if not (0 <= r1 <= r2 < rows and 0 <= c1 <= c2 < cols) or v <= 0:
            raise DiffError("bad rectangle")
        d[r1][c1] += v
        d[r1][c2 + 1] -= v
        d[r2 + 1][c1] -= v
        d[r2 + 1][c2 + 1] += v
    cnt = 0
    grid = [[0] * cols for _ in range(rows)]
    for i in range(rows):
        for j in range(cols):
            v = d[i][j]
            if i > 0:
                v += grid[i - 1][j]
            if j > 0:
                v += grid[i][j - 1]
            if i > 0 and j > 0:
                v -= grid[i - 1][j - 1]
            grid[i][j] = v
            if v > 0:
                cnt += 1
    return cnt

def test_basic():
    assert covered_cells(3, 3, [(0, 0, 1, 1, 1), (2, 2, 2, 2, 1)]) == 5


def test_overlap_counts_once():
    assert covered_cells(2, 2, [(0, 0, 1, 1, 2), (0, 0, 0, 0, 3)]) == 4


def test_no_rects():
    assert covered_cells(2, 2, []) == 0


def test_bad_value():
    try:
        covered_cells(2, 2, [(0, 0, 1, 1, 0)])
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
    test_overlap_counts_once()
    test_no_rects()
    test_bad_value()
    assert stdlib_only()
    print("diff-49 OK: rect-add-covered-count")


if __name__ == "__main__":
    main()
