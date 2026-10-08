"""Second shortest walk (two-distance Dijkstra) (SP-047), Real."""
from __future__ import annotations
import ast

VERSION = "sp-47.v1"

import heapq
INF = float("inf")

def second_shortest(n, adj, src, dst):
    d1 = [INF] * n
    d2 = [INF] * n
    d1[src] = 0
    pq = [(0, src)]
    while pq:
        d, u = heapq.heappop(pq)
        if d > d2[u]:
            continue
        for v, w in adj[u]:
            nd = d + w
            if nd < d1[v]:
                d2[v] = d1[v]
                d1[v] = nd
                heapq.heappush(pq, (nd, v))
            elif d1[v] < nd < d2[v]:
                d2[v] = nd
                heapq.heappush(pq, (nd, v))
    return d2[dst]

def main() -> None:
    adj = [[(1, 1), (2, 2)], [(3, 1)], [(3, 1)], []]
    assert second_shortest(4, adj, 0, 3) == 3
    tri = [[(1, 1), (2, 5)], [(2, 1)], []]
    assert second_shortest(3, tri, 0, 2) == 5
    cyc = [[(1, 1)], [(0, 1), (2, 1)], []]
    assert second_shortest(3, cyc, 0, 2) == 4
    assert second_shortest(3, [[(1, 1)], [], []], 0, 2) == INF
    assert stdlib_only()
    print("sp-47 OK")

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
