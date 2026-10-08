"""A* with Euclidean heuristic on grid (SP-032), Real."""
from __future__ import annotations
import ast

VERSION = "sp-32.v1"

import heapq
import math
INF = float("inf")

def astar_euclid(grid, src, dst):
    R, C = len(grid), len(grid[0])
    def h(r, c):
        return math.hypot(r - dst[0], c - dst[1])
    g = [[INF] * C for _ in range(R)]
    sr, sc = src
    g[sr][sc] = 0
    pq = [(h(sr, sc), 0, sr, sc)]
    while pq:
        f, d, r, c = heapq.heappop(pq)
        if d != g[r][c]:
            continue
        if (r, c) == dst:
            return d
        for dr, dc in ((1, 0), (-1, 0), (0, 1), (0, -1)):
            nr, nc = r + dr, c + dc
            if 0 <= nr < R and 0 <= nc < C and grid[nr][nc] == 0:
                nd = d + 1
                if nd < g[nr][nc]:
                    g[nr][nc] = nd
                    heapq.heappush(pq, (nd + h(nr, nc), nd, nr, nc))
    return INF

def main() -> None:
    g = [[0, 0, 0], [0, 0, 0], [0, 0, 0]]
    assert astar_euclid(g, (0, 0), (2, 2)) == 4
    assert astar_euclid([[0]], (0, 0), (0, 0)) == 0
    g2 = [[0, 1], [1, 0]]
    assert astar_euclid(g2, (0, 0), (1, 1)) == INF
    g3 = [[0, 0, 0, 0]]
    assert astar_euclid(g3, (0, 0), (0, 3)) == 3
    assert stdlib_only()
    print("sp-32 OK")

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
