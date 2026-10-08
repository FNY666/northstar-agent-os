"""Dijkstra on weighted grid (4-direction) (SP-005), Real."""
from __future__ import annotations
import ast

VERSION = "sp-05.v1"

import heapq
INF = float("inf")

def grid_dijkstra(cost, src, dst):
    R, C = len(cost), len(cost[0])
    dist = [[INF] * C for _ in range(R)]
    sr, sc = src
    dist[sr][sc] = cost[sr][sc]
    pq = [(dist[sr][sc], sr, sc)]
    while pq:
        d, r, c = heapq.heappop(pq)
        if d != dist[r][c]:
            continue
        if (r, c) == dst:
            return d
        for dr, dc in ((1, 0), (-1, 0), (0, 1), (0, -1)):
            nr, nc = r + dr, c + dc
            if 0 <= nr < R and 0 <= nc < C and cost[nr][nc] < INF:
                nd = d + cost[nr][nc]
                if nd < dist[nr][nc]:
                    dist[nr][nc] = nd
                    heapq.heappush(pq, (nd, nr, nc))
    return dist[dst[0]][dst[1]]

def main() -> None:
    g = [[1, 1], [1, 1]]
    assert grid_dijkstra(g, (0, 0), (1, 1)) == 3
    assert grid_dijkstra([[5]], (0, 0), (0, 0)) == 5
    g2 = [[1, 9, 1], [1, 9, 1], [1, 1, 1]]
    assert grid_dijkstra(g2, (0, 0), (0, 2)) == 7
    g3 = [[1, INF], [INF, 1]]
    assert grid_dijkstra(g3, (0, 0), (1, 1)) == INF
    assert stdlib_only()
    print("sp-05 OK")

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
