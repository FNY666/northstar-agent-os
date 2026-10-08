"""Johnson's algorithm (reweight + Dijkstra) (SP-019), Real."""
from __future__ import annotations
import ast

VERSION = "sp-19.v1"

import heapq
INF = float("inf")

def johnson(n, edges):
    h = [0] * n
    for _ in range(n - 1):
        for u, v, w in edges:
            if h[u] + w < h[v]:
                h[v] = h[u] + w
    for u, v, w in edges:
        if h[u] + w < h[v]:
            return None
    adj = [[] for _ in range(n)]
    for u, v, w in edges:
        adj[u].append((v, w + h[u] - h[v]))
    alld = []
    for s in range(n):
        dist = [INF] * n
        dist[s] = 0
        pq = [(0, s)]
        while pq:
            d, u = heapq.heappop(pq)
            if d != dist[u]:
                continue
            for v, w in adj[u]:
                nd = d + w
                if nd < dist[v]:
                    dist[v] = nd
                    heapq.heappush(pq, (nd, v))
        alld.append([dist[t] - h[s] + h[t] if dist[t] < INF else INF for t in range(n)])
    return alld

def main() -> None:
    edges = [(0, 1, 4), (0, 2, 1), (1, 2, 2), (2, 3, 1), (1, 3, 5)]
    d = johnson(4, edges)
    assert d[0][3] == 2 and d[0] == [0, 4, 1, 2]
    neg = [(0, 1, 1), (1, 2, -2), (2, 0, 1)]
    d = johnson(3, neg)
    assert d is not None and d[0][2] == -1
    cyc = [(0, 1, 1), (1, 0, -2)]
    assert johnson(2, cyc) is None
    assert johnson(1, []) == [[0]]
    assert stdlib_only()
    print("sp-19 OK")

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
