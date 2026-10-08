"""Swim in rising water (minimax time on grid) (SP-045), Real."""
from __future__ import annotations
import ast

VERSION = "sp-45.v1"

import heapq
INF = float("inf")

def swim(grid):
    R, C = len(grid), len(grid[0])
    best = [[INF] * C for _ in range(R)]
    best[0][0] = grid[0][0]
    pq = [(grid[0][0], 0, 0)]
    while pq:
        t, r, c = heapq.heappop(pq)
        if t != best[r][c]:
            continue
        if (r, c) == (R - 1, C - 1):
            return t
        for dr, dc in ((1, 0), (-1, 0), (0, 1), (0, -1)):
            nr, nc = r + dr, c + dc
            if 0 <= nr < R and 0 <= nc < C:
                nt = max(t, grid[nr][nc])
                if nt < best[nr][nc]:
                    best[nr][nc] = nt
                    heapq.heappush(pq, (nt, nr, nc))
    return best[R - 1][C - 1]

def main() -> None:
    assert swim([[0, 2], [1, 3]]) == 3
    assert swim([[0, 1, 2, 3, 4], [24, 23, 22, 21, 5], [12, 13, 14, 15, 16], [11, 17, 18, 19, 20], [10, 9, 8, 7, 6]]) == 16
    assert swim([[5]]) == 5
    assert swim([[0, 1], [2, 3]]) == 3
    assert stdlib_only()
    print("sp-45 OK")

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
