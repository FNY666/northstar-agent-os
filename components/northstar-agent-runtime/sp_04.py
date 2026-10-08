"""Dijkstra with path reconstruction (SP-004), Real."""
from __future__ import annotations
import ast

VERSION = "sp-04.v1"

import heapq
INF = float("inf")

def dijkstra_path(n, adj, src, dst):
    dist = [INF] * n
    parent = [-1] * n
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
                parent[v] = u
                heapq.heappush(pq, (nd, v))
    if dist[dst] == INF:
        return INF, []
    path = []
    cur = dst
    while cur != -1:
        path.append(cur)
        cur = parent[cur]
    path.reverse()
    return dist[dst], path

def main() -> None:
    adj = [[(1, 4), (2, 1)], [(2, 2), (3, 5)], [(3, 1)], []]
    d, p = dijkstra_path(4, adj, 0, 3)
    assert d == 2 and p == [0, 2, 3]
    d, p = dijkstra_path(4, adj, 0, 0)
    assert d == 0 and p == [0]
    adj2 = [[(1, 1)], [], [(3, 1)], []]
    d, p = dijkstra_path(4, adj2, 0, 3)
    assert d == INF and p == []
    d, p = dijkstra_path(4, adj2, 2, 3)
    assert d == 1 and p == [2, 3]
    assert stdlib_only()
    print("sp-04 OK")

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
