"""Dijkstra naive O(V^2) (SP-001), Real."""
from __future__ import annotations
import ast

VERSION = "sp-01.v1"

INF = float("inf")

def dijkstra_naive(n, adj, src):
    dist = [INF] * n
    done = [False] * n
    dist[src] = 0
    for _ in range(n):
        u = -1
        best = INF
        for i in range(n):
            if not done[i] and dist[i] < best:
                best = dist[i]
                u = i
        if u == -1:
            break
        done[u] = True
        for v, w in adj[u]:
            nd = dist[u] + w
            if nd < dist[v]:
                dist[v] = nd
    return dist

def main() -> None:
    adj = [[(1, 4), (2, 1)], [(2, 2), (3, 5)], [(3, 1)], []]
    assert dijkstra_naive(4, adj, 0) == [0, 4, 1, 2]
    adj2 = [[(1, 1)], [], [(3, 1)], []]
    assert dijkstra_naive(4, adj2, 0) == [0, 1, INF, INF]
    assert dijkstra_naive(1, [[]], 0) == [0]
    line = [[(1, 2)], [(0, 2), (2, 3)], [(1, 3)]]
    assert dijkstra_naive(3, line, 0) == [0, 2, 5]
    assert stdlib_only()
    print("sp-01 OK")

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
