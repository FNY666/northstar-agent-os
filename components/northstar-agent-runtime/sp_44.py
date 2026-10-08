"""Minimum effort path (minimax on grid heights) (SP-044), Real."""
from __future__ import annotations
import ast

VERSION = "sp-44.v1"

import heapq
INF = float("inf")

def min_effort(h):
    R, C = len(h), len(h[0])
    best = [[INF] * C for _ in range(R)]
    best[0][0] = 0
    pq = [(0, 0, 0)]
    while pq:
        e, r, c = heapq.heappop(pq)
        if e != best[r][c]:
            continue
        if (r, c) == (R - 1, C - 1):
            return e
        for dr, dc in ((1, 0), (-1, 0), (0, 1), (0, -1)):
            nr, nc = r + dr, c + dc
            if 0 <= nr < R and 0 <= nc < C:
                ne = max(e, abs(h[nr][nc] - h[r][c]))
                if ne < best[nr][nc]:
                    best[nr][nc] = ne
                    heapq.heappush(pq, (ne, nr, nc))
    return best[R - 1][C - 1]

def main() -> None:
    assert min_effort([[1, 2, 2], [3, 8, 2], [5, 3, 5]]) == 2
    assert min_effort([[1, 2, 3], [3, 8, 4], [5, 3, 5]]) == 1
    assert min_effort([[7]]) == 0
    assert min_effort([[1, 10], [10, 1]]) == 9
    assert stdlib_only()
    print("sp-44 OK")

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
