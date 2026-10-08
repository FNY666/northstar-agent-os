"""Stamp Grid Coverage Check: difference array example.

LeetCode 2132: grid with blocked cells; an h x w stamp may be placed on all-empty regions; 2D difference marks covered cells; every empty cell must be covered.

What this IS: the real 2D-difference coverage check, fail-closed on bad input
What this IS NOT: trying every stamp placement per empty cell
"""

from __future__ import annotations

import ast

#: Module version.
DIFF_29_VERSION = "stamp-grid-cover.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.diff-stamp-grid-cover.v1"


class DiffError(Exception):
    """Fail-closed."""


def can_stamp_cover(grid: list, h: int, w: int) -> bool:
    """grid: 0 = empty, 1 = blocked. True iff stamps cover every empty cell."""
    rows = len(grid)
    cols = len(grid[0]) if rows else 0
    if rows == 0 or cols == 0 or h <= 0 or w <= 0:
        raise DiffError("bad grid or stamp")
    if h > rows or w > cols:
        return all(all(c == 1 for c in row) for row in grid)
    ps = [[0] * (cols + 1) for _ in range(rows + 1)]
    for i in range(rows):
        for j in range(cols):
            ps[i + 1][j + 1] = ps[i][j + 1] + ps[i + 1][j] - ps[i][j] + grid[i][j]

    def rect_sum(r1, c1, r2, c2):
        return ps[r2 + 1][c2 + 1] - ps[r1][c2 + 1] - ps[r2 + 1][c1] + ps[r1][c1]

    d = [[0] * (cols + 1) for _ in range(rows + 1)]
    for i in range(rows - h + 1):
        for j in range(cols - w + 1):
            if rect_sum(i, j, i + h - 1, j + w - 1) == 0:
                d[i][j] += 1
                d[i][j + w] -= 1
                d[i + h][j] -= 1
                d[i + h][j + w] += 1
    cov = [[0] * cols for _ in range(rows)]
    for i in range(rows):
        for j in range(cols):
            v = d[i][j]
            if i > 0:
                v += cov[i - 1][j]
            if j > 0:
                v += cov[i][j - 1]
            if i > 0 and j > 0:
                v -= cov[i - 1][j - 1]
            cov[i][j] = v
    for i in range(rows):
        for j in range(cols):
            if grid[i][j] == 0 and cov[i][j] == 0:
                return False
    return True

def test_coverable():
    grid = [[1, 0, 0, 0], [1, 0, 0, 0], [1, 0, 0, 0], [1, 0, 0, 0], [1, 0, 0, 0]]
    assert can_stamp_cover(grid, 4, 3) is True


def test_not_coverable():
    grid = [[1, 0, 0, 0], [1, 1, 1, 1], [1, 0, 0, 0], [1, 0, 0, 0], [1, 0, 0, 0]]
    assert can_stamp_cover(grid, 4, 3) is False


def test_all_blocked():
    assert can_stamp_cover([[1, 1], [1, 1]], 1, 1) is True


def test_bad():
    try:
        can_stamp_cover([], 1, 1)
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
    test_coverable()
    test_not_coverable()
    test_all_blocked()
    test_bad()
    assert stdlib_only()
    print("diff-29 OK: stamp-grid-cover")


if __name__ == "__main__":
    main()
