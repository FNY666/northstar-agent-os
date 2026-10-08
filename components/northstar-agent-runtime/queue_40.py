"""bfs_grid_shortest: shortest 4-directional path length through a binary grid via BFS, -1 if unreachable. IS: a step count; ragged grid, bad cells, or blocked endpoints raise ValueError. IS NOT: an 8-directional or weighted path search."""

from __future__ import annotations

import ast
from collections import deque
from typing import List, Tuple
VERSION = "queue-40.v1"

def _req_grid(grid: object) -> List[List[int]]:
    if not isinstance(grid, list) or not grid or not all(isinstance(r, list) and r for r in grid):
        raise ValueError("grid must be a non-empty list of non-empty lists")
    width = len(grid[0])
    for row in grid:
        if len(row) != width:
            raise ValueError("grid must be rectangular")
        for cell in row:
            if cell not in (0, 1):
                raise ValueError("cells must be 0 (free) or 1 (blocked)")
    return grid


def bfs_grid_shortest(grid: List[List[int]]) -> int:
    """Return the fewest 4-directional steps from (0,0) to (m-1,n-1)."""
    grid = _req_grid(grid)
    rows, cols = len(grid), len(grid[0])
    if grid[0][0] == 1 or grid[rows - 1][cols - 1] == 1:
        raise ValueError("start and goal cells must be free")
    if rows == 1 and cols == 1:
        return 0
    q: deque = deque([(0, 0, 0)])
    seen = {(0, 0)}
    while q:
        r, c, d = q.popleft()
        for dr, dc in ((1, 0), (-1, 0), (0, 1), (0, -1)):
            nr, nc = r + dr, c + dc
            if (nr, nc) == (rows - 1, cols - 1):
                return d + 1
            if 0 <= nr < rows and 0 <= nc < cols and grid[nr][nc] == 0 and (nr, nc) not in seen:
                seen.add((nr, nc))
                q.append((nr, nc, d + 1))
    return -1


def stdlib_only() -> bool:
    """AST-check: every import in this file resolves to the standard library."""
    import pathlib

    allowed = {"__future__", "ast", "pathlib", "typing", "collections"}
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
    assert bfs_grid_shortest([[0, 0, 0], [1, 1, 0], [0, 0, 0]]) == 4
    assert bfs_grid_shortest([[0, 1], [1, 0]]) == -1
    assert bfs_grid_shortest([[0]]) == 0
    assert bfs_grid_shortest([[0, 0], [0, 0]]) == 2
    try:
        bfs_grid_shortest([[1, 0], [0, 0]])
    except ValueError:
        pass
    else:
        raise AssertionError("blocked start must raise ValueError")
    try:
        bfs_grid_shortest([[0, 0], [0]])
    except ValueError:
        pass
    else:
        raise AssertionError("ragged grid must raise ValueError")
    assert stdlib_only()
    print("queue-40 OK: BFS grid shortest path")


if __name__ == "__main__":
    main()
