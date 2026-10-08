"""Max After Rectangle Adds: difference array example.

2D difference array; report the maximum cell value and its position after all rectangle additions.

What this IS: a real 2D max-after-adds sweep, fail-closed on bad rectangles
What this IS NOT: materializing with nested loops per rectangle
"""

from __future__ import annotations

import ast

#: Module version.
DIFF_28_VERSION = "max-after-rect-adds.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.diff-max-after-rect-adds.v1"


class DiffError(Exception):
    """Fail-closed."""


def max_after_rect_adds(rows: int, cols: int, rects: list) -> tuple:
    """rects: list of (r1, c1, r2, c2, v). Returns (max_value, (r, c))."""
    if rows <= 0 or cols <= 0:
        raise DiffError("rows and cols must be > 0")
    d = [[0] * (cols + 1) for _ in range(rows + 1)]
    for r1, c1, r2, c2, v in rects:
        if not (0 <= r1 <= r2 < rows and 0 <= c1 <= c2 < cols):
            raise DiffError("bad rectangle")
        d[r1][c1] += v
        d[r1][c2 + 1] -= v
        d[r2 + 1][c1] -= v
        d[r2 + 1][c2 + 1] += v
    best = None
    best_rc = (0, 0)
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
            if best is None or v > best:
                best = v
                best_rc = (i, j)
    return best, best_rc

def test_basic():
    assert max_after_rect_adds(2, 2, [(0, 0, 1, 1, 1), (0, 0, 0, 0, 4)]) == (5, (0, 0))


def test_tie_top_left():
    assert max_after_rect_adds(2, 2, [(0, 0, 1, 1, 3)]) == (3, (0, 0))


def test_no_rects():
    assert max_after_rect_adds(2, 3, []) == (0, (0, 0))


def test_bad():
    try:
        max_after_rect_adds(2, 2, [(0, 0, 2, 2, 1)])
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
    test_tie_top_left()
    test_no_rects()
    test_bad()
    assert stdlib_only()
    print("diff-28 OK: max-after-rect-adds")


if __name__ == "__main__":
    main()
