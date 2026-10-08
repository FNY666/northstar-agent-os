"""Flood-fill area: DFS over equal cells

Counts the connected region of the seed cell's value; bounded by grid size.

What this IS: a real recursive flood-fill region counter, fail-closed on bad seeds.
What this IS NOT: a substitute for iterative host code; the host picks the algorithm.
"""

from __future__ import annotations

import ast

#: Module version.
REC_33_VERSION = "rec-flood-area.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.rec-flood-area.v1"


class RecError(Exception):
    """Fail-closed."""


def fill_area(grid, r: int, c: int) -> int:
    """Size of the connected region at (r, c)."""
    rows = len(grid)
    cols = len(grid[0]) if rows else 0
    if not (0 <= r < rows and 0 <= c < cols):
        raise RecError("seed out of bounds")
    target = grid[r][c]
    seen = set()

    def dfs(rr, cc) -> int:
        if not (0 <= rr < rows and 0 <= cc < cols):
            return 0
        if (rr, cc) in seen or grid[rr][cc] != target:
            return 0
        seen.add((rr, cc))
        return 1 + dfs(rr + 1, cc) + dfs(rr - 1, cc) + dfs(rr, cc + 1) + dfs(rr, cc - 1)

    return dfs(r, c)


GRID = [
    [1, 1, 0],
    [1, 0, 0],
    [0, 0, 2],
]

def test_fill_area_basic():
    assert fill_area(GRID, 0, 0) == 3


def test_fill_area_single():
    assert fill_area(GRID, 2, 2) == 1


def test_fill_area_zero_region():
    assert fill_area(GRID, 0, 2) == 5


def test_fill_area_bad_seed():
    try:
        fill_area(GRID, 9, 9)
    except RecError:
        return
    raise AssertionError("expected RecError")

def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib"}
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                if a.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(n, ast.ImportFrom):
            if n.module and n.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    test_fill_area_basic()
    test_fill_area_single()
    test_fill_area_zero_region()
    test_fill_area_bad_seed()
    assert stdlib_only()
    print("rec-flood-area OK")


if __name__ == "__main__":
    main()
