"""Backtracking: Latin square completion (mock).

IS: completes a partially filled n x n grid to a Latin square (symbols
    1..n, no repeated symbol in any row or column) via backtracking.
    Meant for small n.
IS NOT: a Sudoku solver (there is no box constraint) and not an
    enumerator of all Latin squares of a given order.
"""

from __future__ import annotations

import ast
from typing import List, Optional

VERSION = "backtrack_36.v1"


def complete_latin(grid: List[List[int]]) -> Optional[List[List[int]]]:
    """Complete ``grid`` (0 = empty) to a Latin square, or None if impossible.

    Raises ValueError for non-square grids, out-of-range values, or
    contradictory givens (duplicates in a row/column).
    """
    n = len(grid)
    if n == 0:
        raise ValueError("grid must be non-empty")
    for row in grid:
        if len(row) != n:
            raise ValueError("grid must be square")
        for v in row:
            if not 0 <= v <= n:
                raise ValueError("values must be in 0..%d" % n)
    for i in range(n):
        row_vals = [v for v in grid[i] if v]
        col_vals = [grid[r][i] for r in range(n) if grid[r][i]]
        if len(set(row_vals)) != len(row_vals) or len(set(col_vals)) != len(col_vals):
            raise ValueError("contradictory givens")

    g = [row[:] for row in grid]

    def bt() -> bool:
        for i in range(n):
            for j in range(n):
                if g[i][j] == 0:
                    row_used = {g[i][k] for k in range(n) if g[i][k]}
                    col_used = {g[k][j] for k in range(n) if g[k][j]}
                    for v in range(1, n + 1):
                        if v not in row_used and v not in col_used:
                            g[i][j] = v
                            if bt():
                                return True
                            g[i][j] = 0
                    return False
        return True

    return [row[:] for row in g] if bt() else None


def is_latin(grid: List[List[int]]) -> bool:
    """True when ``grid`` is a complete Latin square."""
    n = len(grid)
    want = set(range(1, n + 1))
    return all(set(row) == want for row in grid) and all(
        {grid[r][c] for r in range(n)} == want for c in range(n))


def stdlib_only() -> bool:
    """Parse this file with ast; True only if every import is allowed."""
    allowed = {"__future__", "ast", "typing"}
    with open(__file__) as fh:
        tree = ast.parse(fh.read())
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
    # empty 3x3 -> some valid Latin square
    sol = complete_latin([[0] * 3 for _ in range(3)])
    assert sol is not None and is_latin(sol)
    # partial 3x3 on the diagonal -> completable, givens preserved
    givens = [[1, 0, 0], [0, 2, 0], [0, 0, 3]]
    sol2 = complete_latin(givens)
    assert sol2 is not None and is_latin(sol2)
    assert sol2[0][0] == 1 and sol2[1][1] == 2 and sol2[2][2] == 3
    # valid but uncompletable 2x2: row 0 needs 2 at col 1, col 1 already has 2
    assert complete_latin([[1, 0], [0, 2]]) is None
    # contradictory givens -> ValueError
    try:
        complete_latin([[1, 1, 0], [0, 0, 0], [0, 0, 0]])
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for duplicate givens")
    # non-square -> ValueError
    try:
        complete_latin([[1, 0], [0]])
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for non-square grid")
    assert stdlib_only()
    print("backtrack_36 OK")


if __name__ == "__main__":
    main()
