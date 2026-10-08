"""count_islands_bfs: number of 4-connected islands of '1's in a binary grid via BFS. IS: an island count; ragged grid or bad cells raise ValueError. IS NOT: a union-find island count (this is the BFS version)."""

from __future__ import annotations

import ast
from collections import deque
from typing import List
VERSION = "queue-45.v1"

def _req_grid(grid: object) -> List[List[str]]:
    if not isinstance(grid, list) or not grid:
        raise ValueError("grid must be a non-empty list of lists")
    width = len(grid[0])
    norm = []
    for row in grid:
        if not isinstance(row, list) or len(row) != width or not row:
            raise ValueError("grid must be rectangular")
        nrow = []
        for cell in row:
            if cell in (1, "1"):
                nrow.append("1")
            elif cell in (0, "0"):
                nrow.append("0")
            else:
                raise ValueError("cells must be 0/1")
        norm.append(nrow)
    return norm


def count_islands_bfs(grid: List[List[str]]) -> int:
    """Return the number of 4-connected ``'1'`` regions."""
    grid = _req_grid(grid)
    rows, cols = len(grid), len(grid[0])
    islands = 0
    for r in range(rows):
        for c in range(cols):
            if grid[r][c] != "1":
                continue
            islands += 1
            q: deque = deque([(r, c)])
            grid[r][c] = "0"
            while q:
                cr, cc = q.popleft()
                for dr, dc in ((1, 0), (-1, 0), (0, 1), (0, -1)):
                    nr, nc = cr + dr, cc + dc
                    if 0 <= nr < rows and 0 <= nc < cols and grid[nr][nc] == "1":
                        grid[nr][nc] = "0"
                        q.append((nr, nc))
    return islands


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
    assert count_islands_bfs([["1", "1", "0"], ["0", "1", "0"], ["1", "0", "1"]]) == 3
    assert count_islands_bfs([[1, 1, 1], [1, 1, 1]]) == 1
    assert count_islands_bfs([["0", "0"], ["0", "0"]]) == 0
    assert count_islands_bfs([["1"]]) == 1
    try:
        count_islands_bfs([["1"], ["1", "0"]])
    except ValueError:
        pass
    else:
        raise AssertionError("ragged grid must raise ValueError")
    try:
        count_islands_bfs([["2"]])
    except ValueError:
        pass
    else:
        raise AssertionError("bad cell must raise ValueError")
    assert stdlib_only()
    print("queue-45 OK: BFS island count")


if __name__ == "__main__":
    main()
