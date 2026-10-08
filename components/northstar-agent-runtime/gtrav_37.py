"""Flood fill via DFS on a grid. IS: repaints the connected open region and returns the filled count. IS NOT: BFS fill; see gtrav_36."""

from __future__ import annotations

import ast

VERSION = "gtrav-37.v1"

def _req_grid(grid: object) -> list:
    """Fail-closed: grid must be a non-empty rectangular list of lists of 0/1."""
    if not isinstance(grid, list) or not grid:
        raise ValueError("grid must be a non-empty list of lists")
    width = None
    for row in grid:
        if not isinstance(row, list) or not row:
            raise ValueError("grid rows must be non-empty lists")
        if width is None:
            width = len(row)
        elif len(row) != width:
            raise ValueError("grid must be rectangular")
        for cell in row:
            if cell not in (0, 1):
                raise ValueError("grid cells must be 0 (open) or 1 (wall)")
    return grid


def _req_cell(grid: list, cell: object, name: str) -> tuple:
    if (
        not isinstance(cell, (list, tuple))
        or len(cell) != 2
        or not all(isinstance(v, int) for v in cell)
    ):
        raise ValueError(name + " must be a (row, col) pair of ints")
    r, c = int(cell[0]), int(cell[1])
    if not (0 <= r < len(grid) and 0 <= c < len(grid[0])):
        raise ValueError(name + " is out of grid bounds")
    if grid[r][c] != 0:
        raise ValueError(name + " must be an open cell")
    return (r, c)

_DIRS4 = [(1, 0), (-1, 0), (0, 1), (0, -1)]


def flood_fill_dfs(grid: object, start: object, new_val: object = 2) -> int:
    """Fill the connected region of start with new_val; return filled count."""
    grid = _req_grid(grid)
    sr, sc = _req_cell(grid, start, "start")
    if not isinstance(new_val, int):
        raise ValueError("new_val must be an int")
    old = grid[sr][sc]
    if old == new_val:
        return 0
    count = 0
    stack: list = [(sr, sc)]
    while stack:
        r, c = stack.pop()
        if grid[r][c] != old:
            continue
        grid[r][c] = new_val
        count += 1
        for dr, dc in _DIRS4:
            nr, nc = r + dr, c + dc
            if 0 <= nr < len(grid) and 0 <= nc < len(grid[0]) and grid[nr][nc] == old:
                stack.append((nr, nc))
    return count


def stdlib_only() -> bool:
    """AST-check: no imports outside the allowed stdlib set."""
    import pathlib

    allowed = {"__future__", "ast", "pathlib", "typing"}
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"))
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
    grid = [[0, 0, 1], [0, 1, 1], [1, 1, 1]]
    assert flood_fill_dfs(grid, (0, 0)) == 3
    assert grid[0][1] == 2
    assert flood_fill_dfs([[0]], (0, 0), 7) == 1
    try:
        flood_fill_dfs([[0, 2]], (0, 0))
    except ValueError:
        pass
    else:
        raise AssertionError("cell value 2 must raise ValueError")
    assert flood_fill_dfs([[0]], (0, 0), 0) == 0
    assert stdlib_only()
    print("gtrav_37 OK")


if __name__ == "__main__":
    main()
