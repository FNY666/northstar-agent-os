"""A* with zero heuristic equals Dijkstra (SP-033), Real."""
from __future__ import annotations
import ast

VERSION = "sp-33.v1"

import heapq
INF = float("inf")

def astar(n, adj, src, dst, h):
    g = [INF] * n
    g[src] = 0
    pq = [(h(src), 0, src)]
    while pq:
        f, d, u = heapq.heappop(pq)
        if d != g[u]:
            continue
        if u == dst:
            return d
        for v, w in adj[u]:
            nd = d + w
            if nd < g[v]:
                g[v] = nd
                heapq.heappush(pq, (nd + h(v), nd, v))
    return INF

def main() -> None:
    adj = [[(1, 4), (2, 1)], [(2, 2), (3, 5)], [(3, 1)], []]
    zero = lambda v: 0
    assert astar(4, adj, 0, 3, zero) == 2
    heur = {0: 2, 1: 3, 2: 1, 3: 0}
    assert astar(4, adj, 0, 3, lambda v: heur[v]) == 2
    assert astar(4, adj, 0, 0, zero) == 0
    adj2 = [[(1, 1)], [], []]
    assert astar(3, adj2, 0, 2, zero) == INF
    assert stdlib_only()
    print("sp-33 OK")

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
