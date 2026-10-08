"""BFS on an 8-directional grid. IS: traversal including diagonals. IS NOT: 4-directional; see gtrav_15."""

from __future__ import annotations

import ast

VERSION = "gtrav-17.v1"

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

_DIRS8 = [(1, 0), (-1, 0), (0, 1), (0, -1), (1, 1), (1, -1), (-1, 1), (-1, -1)]


def bfs_grid8(grid: object, start: object) -> list:
    """Return open cells reachable from start using 8 directions."""
    grid = _req_grid(grid)
    sr, sc = _req_cell(grid, start, "start")
    order: list = []
    seen: set = {(sr, sc)}
    queue: list = [(sr, sc)]
    while queue:
        r, c = queue.pop(0)
        order.append((r, c))
        for dr, dc in _DIRS8:
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
    grid = [[0, 1, 0], [1, 1, 0], [0, 0, 0]]
    # 4-dir from (0,0) is isolated; 8-dir reaches (1,2) diagonally via (0,0)->(1,2)? no:
    # (0,0) neighbors 8-dir: (1,1) wall. isolated.
    assert bfs_grid8(grid, (0, 0)) == [(0, 0)]
    grid2 = [[0, 1], [1, 0]]
    assert set(bfs_grid8(grid2, (0, 0))) == {(0, 0), (1, 1)}
    assert bfs_grid8([[0]], (0, 0)) == [(0, 0)]
    try:
        bfs_grid8(grid, (0, 1))
    except ValueError:
        pass
    else:
        raise AssertionError("wall start must raise ValueError")
    assert stdlib_only()
    print("gtrav_17 OK")


if __name__ == "__main__":
    main()
