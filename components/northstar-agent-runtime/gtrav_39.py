"""Maze path via DFS. IS: a path from start to goal through open cells, or None. IS NOT: the shortest path; see gtrav_40."""

from __future__ import annotations

import ast

VERSION = "gtrav-39.v1"

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


def dfs_maze(maze: object, start: object, goal: object) -> object:
    """Return a DFS path from start to goal, or None."""
    maze = _req_grid(maze)
    sr, sc = _req_cell(maze, start, "start")
    gr, gc = _req_cell(maze, goal, "goal")
    seen: set = set()

    def visit(r: int, c: int) -> object:
        if (r, c) == (gr, gc):
            return [(r, c)]
        seen.add((r, c))
        for dr, dc in _DIRS4:
            nr, nc = r + dr, c + dc
            if 0 <= nr < len(maze) and 0 <= nc < len(maze[0]):
                if maze[nr][nc] == 0 and (nr, nc) not in seen:
                    sub = visit(nr, nc)
                    if sub is not None:
                        return [(r, c)] + sub
        return None

    return visit(sr, sc)


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
    maze = [[0, 0, 1], [1, 0, 1], [1, 0, 0]]
    p = dfs_maze(maze, (0, 0), (2, 2))
    assert p is not None and p[0] == (0, 0) and p[-1] == (2, 2)
    assert dfs_maze([[0]], (0, 0), (0, 0)) == [(0, 0)]
    assert dfs_maze([[0, 1], [1, 0]], (0, 0), (1, 1)) is None
    try:
        dfs_maze(maze, (0, 0), (0, 2))
    except ValueError:
        pass
    else:
        raise AssertionError("wall goal must raise ValueError")
    assert stdlib_only()
    print("gtrav_39 OK")


if __name__ == "__main__":
    main()
