"""BFS on a 4-directional grid. IS: flood traversal of open cells (0) avoiding walls (1). IS NOT: 8-directional; see gtrav_17."""

from __future__ import annotations

import ast

VERSION = "gtrav-15.v1"

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


def bfs_grid4(grid: object, start: object) -> list:
    """Return open cells reachable from start in BFS order."""
    grid = _req_grid(grid)
    sr, sc = _req_cell(grid, start, "start")
    order: list = []
    seen: set = {(sr, sc)}
    queue: list = [(sr, sc)]
    while queue:
        r, c = queue.pop(0)
        order.append((r, c))
        for dr, dc in _DIRS4:
            nr, nc = r + dr, c + dc
            if 0 <= nr < len(grid) and 0 <= nc < len(grid[0]):
                if grid[nr][nc] == 0 and (nr, nc) not in seen:
                    seen.add((nr, nc))
                    queue.append((nr, nc))
    return order


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
    grid = [[0, 0, 1], [0, 1, 0], [0, 0, 0]]
    assert bfs_grid4(grid, (0, 0)) == [(0, 0), (1, 0), (0, 1), (2, 0), (2, 1), (2, 2), (1, 2)]
    assert bfs_grid4([[0]], (0, 0)) == [(0, 0)]
    assert len(bfs_grid4(grid, (2, 2))) == 7
    try:
        bfs_grid4(grid, (0, 2))
    except ValueError:
        pass
    else:
        raise AssertionError("wall start must raise ValueError")
    try:
        bfs_grid4([[0, 1], [0]], (0, 0))
    except ValueError:
        pass
    else:
        raise AssertionError("ragged grid must raise ValueError")
    assert stdlib_only()
    print("gtrav_15 OK")


if __name__ == "__main__":
    main()
