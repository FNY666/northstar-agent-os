"""BFS on grid with obstacles (SP-029), Real."""
from __future__ import annotations
import ast

VERSION = "sp-29.v1"

from collections import deque
INF = float("inf")

def grid_bfs(grid, src, dst):
    R, C = len(grid), len(grid[0])
    dist = [[-1] * C for _ in range(R)]
    sr, sc = src
    if grid[sr][sc] == 1:
        return -1
    dist[sr][sc] = 0
    q = deque([(sr, sc)])
    while q:
        r, c = q.popleft()
        if (r, c) == dst:
            return dist[r][c]
        for dr, dc in ((1, 0), (-1, 0), (0, 1), (0, -1)):
            nr, nc = r + dr, c + dc
            if 0 <= nr < R and 0 <= nc < C and grid[nr][nc] == 0 and dist[nr][nc] == -1:
                dist[nr][nc] = dist[r][c] + 1
                q.append((nr, nc))
    return -1

def main() -> None:
    g = [[0, 0], [0, 0]]
    assert grid_bfs(g, (0, 0), (1, 1)) == 2
    g2 = [[0, 1, 0], [0, 1, 0], [0, 0, 0]]
    assert grid_bfs(g2, (0, 0), (0, 2)) == 6
    assert grid_bfs([[0]], (0, 0), (0, 0)) == 0
    g3 = [[0, 1], [1, 0]]
    assert grid_bfs(g3, (0, 0), (1, 1)) == -1
    assert stdlib_only()
    print("sp-29 OK")

def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib", "typing", "heapq", "collections", "math", "itertools", "functools", "dataclasses"}
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                if a.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(n, ast.ImportFrom):
            if n.module and n.module.split(".")[0] not in allowed:
                return False
    return True


if __name__ == "__main__":
    main()
