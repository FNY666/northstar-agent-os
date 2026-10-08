"""Dijkstra with binary heap (SP-002), Real."""
from __future__ import annotations
import ast

VERSION = "sp-02.v1"

import heapq
INF = float("inf")

def dijkstra_heap(n, adj, src):
    dist = [INF] * n
    dist[src] = 0
    pq = [(0, src)]
    while pq:
        d, u = heapq.heappop(pq)
        if d != dist[u]:
            continue
        for v, w in adj[u]:
            nd = d + w
            if nd < dist[v]:
                dist[v] = nd
                heapq.heappush(pq, (nd, v))
    return dist

def main() -> None:
    adj = [[(1, 4), (2, 1)], [(2, 2), (3, 5)], [(3, 1)], []]
    assert dijkstra_heap(4, adj, 0) == [0, 4, 1, 2]
    adj2 = [[(1, 1)], [], [(3, 1)], []]
    assert dijkstra_heap(4, adj2, 0) == [0, 1, INF, INF]
    assert dijkstra_heap(1, [[]], 0) == [0]
    star = [[(1, 1), (2, 2), (3, 3)], [], [], []]
    assert dijkstra_heap(4, star, 0) == [0, 1, 2, 3]
    assert stdlib_only()
    print("sp-02 OK")

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
