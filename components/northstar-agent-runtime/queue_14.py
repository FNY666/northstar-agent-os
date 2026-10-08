"""rotten_oranges: minutes until all oranges rot via multi-source BFS, -1 if impossible. IS: a BFS minute count; ragged grid or bad cell values raise ValueError. IS NOT: a DFS-based or per-orange simulation."""

from __future__ import annotations

import ast
from collections import deque
from typing import List, Tuple
VERSION = "queue-14.v1"

def _req_grid(grid: object) -> List[List[int]]:
    if not isinstance(grid, list) or not grid or not all(isinstance(r, list) and r for r in grid):
        raise ValueError("grid must be a non-empty list of non-empty lists")
    width = len(grid[0])
    for row in grid:
        if len(row) != width:
            raise ValueError("grid must be rectangular")
        for cell in row:
            if cell not in (0, 1, 2):
                raise ValueError("cells must be 0, 1, or 2")
    return grid


def rotten_oranges(grid: List[List[int]]) -> int:
    """Return minutes to rot every fresh orange, ``-1`` if some never rot."""
    grid = _req_grid(grid)
    rows, cols = len(grid), len(grid[0])
    q: deque = deque()
    fresh = 0
    for r in range(rows):
        for c in range(cols):
            if grid[r][c] == 2:
                q.append((r, c, 0))
            elif grid[r][c] == 1:
                fresh += 1
    minutes = 0
    while q:
        r, c, t = q.popleft()
        minutes = max(minutes, t)
        for dr, dc in ((1, 0), (-1, 0), (0, 1), (0, -1)):
            nr, nc = r + dr, c + dc
            if 0 <= nr < rows and 0 <= nc < cols and grid[nr][nc] == 1:
                grid[nr][nc] = 2
                fresh -= 1
                q.append((nr, nc, t + 1))
    return minutes if fresh == 0 else -1


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
    assert rotten_oranges([[2, 1, 1], [1, 1, 0], [0, 1, 1]]) == 4
    assert rotten_oranges([[2, 1, 1], [0, 1, 1], [1, 0, 1]]) == -1
    assert rotten_oranges([[0, 2]]) == 0
    assert rotten_oranges([[1]]) == -1
    try:
        rotten_oranges([[1, 2], [1]])
    except ValueError:
        pass
    else:
        raise AssertionError("ragged grid must raise ValueError")
    try:
        rotten_oranges([[1, 3]])
    except ValueError:
        pass
    else:
        raise AssertionError("bad cell value must raise ValueError")
    assert stdlib_only()
    print("queue-14 OK: multi-source BFS rot")


if __name__ == "__main__":
    main()
