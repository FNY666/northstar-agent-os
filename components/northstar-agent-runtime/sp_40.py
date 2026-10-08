"""Shortest path in binary matrix (8-direction BFS) (SP-040), Real."""
from __future__ import annotations
import ast

VERSION = "sp-40.v1"

from collections import deque
INF = float("inf")

def binary_matrix(grid):
    R, C = len(grid), len(grid[0])
    if grid[0][0] == 1 or grid[R - 1][C - 1] == 1:
        return -1
    dist = [[-1] * C for _ in range(R)]
    dist[0][0] = 1
    q = deque([(0, 0)])
    while q:
        r, c = q.popleft()
        if (r, c) == (R - 1, C - 1):
            return dist[r][c]
        for dr in (-1, 0, 1):
            for dc in (-1, 0, 1):
                if dr == 0 and dc == 0:
                    continue
                nr, nc = r + dr, c + dc
                if 0 <= nr < R and 0 <= nc < C and grid[nr][nc] == 0 and dist[nr][nc] == -1:
                    dist[nr][nc] = dist[r][c] + 1
                    q.append((nr, nc))
    return -1

def main() -> None:
    assert binary_matrix([[0, 1], [1, 0]]) == 2
    assert binary_matrix([[0, 0, 0], [1, 1, 0], [1, 1, 0]]) == 4
    assert binary_matrix([[1, 0], [0, 0]]) == -1
    assert binary_matrix([[0]]) == 1
    assert stdlib_only()
    print("sp-40 OK")

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
