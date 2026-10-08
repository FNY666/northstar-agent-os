"""Dijkstra counting number of shortest paths (SP-006), Real."""
from __future__ import annotations
import ast

VERSION = "sp-06.v1"

import heapq
INF = float("inf")

def dijkstra_count(n, adj, src):
    dist = [INF] * n
    cnt = [0] * n
    dist[src] = 0
    cnt[src] = 1
    pq = [(0, src)]
    while pq:
        d, u = heapq.heappop(pq)
        if d > dist[u]:
            continue
        for v, w in adj[u]:
            nd = d + w
            if nd < dist[v]:
                dist[v] = nd
                cnt[v] = cnt[u]
                heapq.heappush(pq, (nd, v))
            elif nd == dist[v]:
                cnt[v] += cnt[u]
    return dist, cnt

def main() -> None:
    diamond = [[(1, 1), (2, 1)], [(3, 1)], [(3, 1)], []]
    d, c = dijkstra_count(4, diamond, 0)
    assert d[3] == 2 and c[3] == 2
    line = [[(1, 1)], [(2, 1)], []]
    d, c = dijkstra_count(3, line, 0)
    assert d[2] == 2 and c[2] == 1
    tri = [[(1, 1), (2, 2)], [(2, 1)], []]
    d, c = dijkstra_count(3, tri, 0)
    assert d[2] == 2 and c[2] == 2
    assert dijkstra_count(1, [[]], 0) == ([0], [1])
    assert stdlib_only()
    print("sp-06 OK")

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
