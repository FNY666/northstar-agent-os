"""Dijkstra with lexicographically smallest shortest path (SP-007), Real."""
from __future__ import annotations
import ast

VERSION = "sp-07.v1"

import heapq
INF = float("inf")

def dijkstra_lex(n, adj, src, dst):
    dist = [INF] * n
    best_path = [None] * n
    dist[src] = 0
    best_path[src] = (src,)
    pq = [(0, (src,), src)]
    while pq:
        d, pth, u = heapq.heappop(pq)
        if (d, pth) != (dist[u], best_path[u]):
            continue
        for v, w in adj[u]:
            nd = d + w
            npth = pth + (v,)
            if nd < dist[v] or (nd == dist[v] and npth < best_path[v]):
                dist[v] = nd
                best_path[v] = npth
                heapq.heappush(pq, (nd, npth, v))
    return dist[dst], list(best_path[dst]) if best_path[dst] else []

def main() -> None:
    adj = [[(1, 1), (2, 1)], [(3, 1)], [(3, 1)], []]
    d, p = dijkstra_lex(4, adj, 0, 3)
    assert d == 2 and p == [0, 1, 3]
    adj2 = [[(2, 1), (1, 1)], [(3, 1)], [(3, 1)], []]
    d, p = dijkstra_lex(4, adj2, 0, 3)
    assert d == 2 and p == [0, 1, 3]
    d, p = dijkstra_lex(4, adj, 1, 1)
    assert d == 0 and p == [1]
    adj3 = [[(1, 1)], [], []]
    d, p = dijkstra_lex(3, adj3, 0, 2)
    assert d == INF and p == []
    assert stdlib_only()
    print("sp-07 OK")

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
