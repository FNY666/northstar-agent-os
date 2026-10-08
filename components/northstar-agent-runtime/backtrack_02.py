"""Backtracking: Sudoku solver.

Solves a standard 9x9 Sudoku puzzle given as a 9x9 grid with 0 for empty
cells, using backtracking with row/column/3x3-box validity checks.

IS: a complete search that solves solvable puzzles; returns solved grid.
IS NOT: a generator, a uniqueness checker, or a killer/x-variant solver.
"""

from typing import List, Optional
import ast

VERSION = "backtrack_02.v1"

Grid = List[List[int]]


def is_valid(grid: Grid, r: int, c: int, val: int) -> bool:
    for i in range(9):
        if grid[r][i] == val or grid[i][c] == val:
            return False
    br, bc = 3 * (r // 3), 3 * (c // 3)
    for i in range(br, br + 3):
        for j in range(bc, bc + 3):
            if grid[i][j] == val:
                return False
    return True


def find_empty(grid: Grid) -> Optional[tuple]:
    for r in range(9):
        for c in range(9):
            if grid[r][c] == 0:
                return (r, c)
    return None


def solve_sudoku(grid: Grid) -> bool:
    """Solve in place; return True if a solution was found."""
    empty = find_empty(grid)
    if empty is None:
        return True
    r, c = empty
    for val in range(1, 10):
        if is_valid(grid, r, c, val):
            grid[r][c] = val
            if solve_sudoku(grid):
                return True
            grid[r][c] = 0
    return False


KNOWN_PUZZLE: Grid = [
    [5, 3, 0, 0, 7, 0, 0, 0, 0],
    [6, 0, 0, 1, 9, 5, 0, 0, 0],
    [0, 9, 8, 0, 0, 0, 0, 6, 0],
    [8, 0, 0, 0, 6, 0, 0, 0, 3],
    [4, 0, 0, 8, 0, 3, 0, 0, 1],
    [7, 0, 0, 0, 2, 0, 0, 0, 6],
    [0, 6, 0, 0, 0, 0, 2, 8, 0],
    [0, 0, 0, 4, 1, 9, 0, 0, 5],
    [0, 0, 0, 0, 8, 0, 0, 7, 9],
]

KNOWN_SOLUTION: Grid = [
    [5, 3, 4, 6, 7, 8, 9, 1, 2],
    [6, 7, 2, 1, 9, 5, 3, 4, 8],
    [1, 9, 8, 3, 4, 2, 5, 6, 7],
    [8, 5, 9, 7, 6, 1, 4, 2, 3],
    [4, 2, 6, 8, 5, 3, 7, 9, 1],
    [7, 1, 3, 9, 2, 4, 8, 5, 6],
    [9, 6, 1, 5, 3, 7, 2, 8, 4],
    [2, 8, 7, 4, 1, 9, 6, 3, 5],
    [3, 4, 5, 2, 8, 6, 1, 7, 9],
]


def stdlib_only() -> bool:
    allowed = {"typing", "ast"}
    with open(__file__) as f:
        tree = ast.parse(f.read())
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
    grid = [row[:] for row in KNOWN_PUZZLE]
    assert solve_sudoku(grid)
    assert grid == KNOWN_SOLUTION
    solved = [row[:] for row in KNOWN_SOLUTION]
    assert solve_sudoku(solved)
    assert solved == KNOWN_SOLUTION
    assert not is_valid(KNOWN_SOLUTION, 0, 2, 5)
    assert stdlib_only()
    print("backtrack_02 OK")


if __name__ == "__main__":
    main()
