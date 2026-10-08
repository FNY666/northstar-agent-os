"""Perimeter of a grid region via DFS. IS: counts exposed sides of the connected open region. IS NOT: the region cells themselves; see gtrav_16."""

from __future__ import annotations

import ast

VERSION = "gtrav-49.v1"

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


def dfs_perimeter(grid: object, start: object) -> int:
    """Return the perimeter of the open region containing start."""
    grid = _req_grid(grid)
    sr, sc = _req_cell(grid, start, "start")
    seen: set = set()
    stack: list = [(sr, sc)]
    perimeter = 0
    while stack:
        r, c = stack.pop()
        if (r, c) in seen:
            continue
        seen.add((r, c))
        for dr, dc in _DIRS4:
            nr, nc = r + dr, c + dc
            if 0 <= nr < len(grid) and 0 <= nc < len(grid[0]) and grid[nr][nc] == 0:
                if (nr, nc) not in seen:
                    stack.append((nr, nc))
            else:
                perimeter += 1
    return perimeter


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
    assert dfs_perimeter([[0]], (0, 0)) == 4
    assert dfs_perimeter([[0, 0], [0, 0]], (0, 0)) == 8
    assert dfs_perimeter([[0, 0, 1], [0, 0, 1]], (0, 0)) == 8
    try:
        dfs_perimeter([[0]], (0, 0) if False else (2, 2))
    except ValueError:
        pass
    else:
        raise AssertionError("out-of-bounds start must raise ValueError")
    try:
        dfs_perimeter("grid", (0, 0))
    except ValueError:
        pass
    else:
        raise AssertionError("non-list grid must raise ValueError")
    assert stdlib_only()
    print("gtrav_49 OK")


if __name__ == "__main__":
    main()
