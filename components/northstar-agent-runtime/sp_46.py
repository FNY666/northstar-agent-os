"""Shortest path with alternating colors (BFS state) (SP-046), Real."""
from __future__ import annotations
import ast

VERSION = "sp-46.v1"

from collections import deque
INF = float("inf")

def alt_colors(n, red, blue, src, dst):
    radj = [[] for _ in range(n)]
    badj = [[] for _ in range(n)]
    for u, v in red:
        radj[u].append(v)
    for u, v in blue:
        badj[u].append(v)
    dist = [[INF, INF] for _ in range(n)]
    q = deque()
    for c in (0, 1):
        dist[src][c] = 0
        q.append((src, c))
    while q:
        u, last = q.popleft()
        nxt = badj[u] if last == 0 else radj[u]
        nc = 1 - last
        for v in nxt:
            if dist[v][nc] == INF:
                dist[v][nc] = dist[u][last] + 1
                q.append((v, nc))
    ans = min(dist[dst])
    return ans if ans < INF else -1

def main() -> None:
    assert alt_colors(3, [(0, 1), (1, 2)], [(0, 2)], 0, 2) == 1
    assert alt_colors(3, [(0, 1)], [(1, 2)], 0, 2) == 2
    assert alt_colors(3, [(0, 1)], [(0, 2)], 0, 2) == 1
    assert alt_colors(3, [(0, 1)], [], 0, 2) == -1
    assert stdlib_only()
    print("sp-46 OK")

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
