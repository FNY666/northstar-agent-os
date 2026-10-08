"""Maze shortest path via BFS. IS: fewest-steps path through open cells, or None. IS NOT: DFS first-found path; see gtrav_39."""

from __future__ import annotations

import ast

VERSION = "gtrav-40.v1"

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


def bfs_maze(maze: object, start: object, goal: object) -> object:
    """Return the shortest path from start to goal, or None."""
    maze = _req_grid(maze)
    sr, sc = _req_cell(maze, start, "start")
    gr, gc = _req_cell(maze, goal, "goal")
    if (sr, sc) == (gr, gc):
        return [(sr, sc)]
    seen: set = {(sr, sc)}
    queue: list = [((sr, sc), [(sr, sc)])]
    while queue:
        (r, c), path = queue.pop(0)
        for dr, dc in _DIRS4:
            nr, nc = r + dr, c + dc
            if 0 <= nr < len(maze) and 0 <= nc < len(maze[0]):
                if maze[nr][nc] == 0 and (nr, nc) not in seen:
                    if (nr, nc) == (gr, gc):
                        return path + [(nr, nc)]
                    seen.add((nr, nc))
                    queue.append(((nr, nc), path + [(nr, nc)]))
    return None


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
    assert bfs_maze(maze, (0, 0), (2, 2)) == [(0, 0), (0, 1), (1, 1), (2, 1), (2, 2)]
    assert bfs_maze([[0]], (0, 0), (0, 0)) == [(0, 0)]
    assert bfs_maze([[0, 1], [1, 0]], (0, 0), (1, 1)) is None
    try:
        bfs_maze(maze, (9, 9), (2, 2))
    except ValueError:
        pass
    else:
        raise AssertionError("out-of-bounds start must raise ValueError")
    assert stdlib_only()
    print("gtrav_40 OK")


if __name__ == "__main__":
    main()
