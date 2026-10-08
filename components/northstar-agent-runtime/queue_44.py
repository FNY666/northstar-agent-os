"""flood_fill_bfs: BFS flood fill: recolor the 4-connected region of the start pixel. IS: a new recolored image (input untouched); out-of-bounds start raises ValueError. IS NOT: a recursive DFS fill (this is the queue version)."""

from __future__ import annotations

import ast
from collections import deque
from typing import List
VERSION = "queue-44.v1"

def _req_image(image: object) -> List[List[int]]:
    if not isinstance(image, list) or not image:
        raise ValueError("image must be a non-empty list of lists")
    width = len(image[0])
    for row in image:
        if not isinstance(row, list) or len(row) != width:
            raise ValueError("image must be rectangular")
        for cell in row:
            if isinstance(cell, bool) or not isinstance(cell, int):
                raise ValueError("pixels must be ints")
    return [list(row) for row in image]


def flood_fill_bfs(image: List[List[int]], sr: int, sc: int, new_color: int) -> List[List[int]]:
    """Return a copy of ``image`` with the (sr, sc) region set to ``new_color``."""
    grid = _req_image(image)
    rows, cols = len(grid), len(grid[0])
    for name, v, lo, hi in (("sr", sr, 0, rows - 1), ("sc", sc, 0, cols - 1)):
        if isinstance(v, bool) or not isinstance(v, int) or not lo <= v <= hi:
            raise ValueError(f"{name} out of bounds")
    if isinstance(new_color, bool) or not isinstance(new_color, int):
        raise ValueError("new_color must be an int")
    old = grid[sr][sc]
    if old == new_color:
        return grid
    q: deque = deque([(sr, sc)])
    grid[sr][sc] = new_color
    while q:
        r, c = q.popleft()
        for dr, dc in ((1, 0), (-1, 0), (0, 1), (0, -1)):
            nr, nc = r + dr, c + dc
            if 0 <= nr < rows and 0 <= nc < cols and grid[nr][nc] == old:
                grid[nr][nc] = new_color
                q.append((nr, nc))
    return grid


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
    img = [[1, 1, 1], [1, 1, 0], [1, 0, 1]]
    assert flood_fill_bfs(img, 1, 1, 2) == [[2, 2, 2], [2, 2, 0], [2, 0, 1]]
    assert img == [[1, 1, 1], [1, 1, 0], [1, 0, 1]]  # input untouched
    assert flood_fill_bfs(img, 0, 0, 1) == img  # same color -> copy
    assert flood_fill_bfs([[0]], 0, 0, 7) == [[7]]
    try:
        flood_fill_bfs(img, 5, 0, 2)
    except ValueError:
        pass
    else:
        raise AssertionError("out-of-bounds sr must raise ValueError")
    try:
        flood_fill_bfs([[1, 2], [3]], 0, 0, 9)
    except ValueError:
        pass
    else:
        raise AssertionError("ragged image must raise ValueError")
    assert stdlib_only()
    print("queue-44 OK: BFS flood fill")


if __name__ == "__main__":
    main()
