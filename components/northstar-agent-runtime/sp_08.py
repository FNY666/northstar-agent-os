"""Bidirectional Dijkstra (SP-008), Real."""
from __future__ import annotations
import ast

VERSION = "sp-08.v1"

import heapq
INF = float("inf")

def _rev(adj, n):
    r = [[] for _ in range(n)]
    for u in range(n):
        for v, w in adj[u]:
            r[v].append((u, w))
    return r

def bidir_dijkstra(n, adj, src, dst):
    if src == dst:
        return 0
    radj = _rev(adj, n)
    df = [INF] * n
    db = [INF] * n
    df[src] = 0
    db[dst] = 0
    pf = [(0, src)]
    pb = [(0, dst)]
    done_f = [False] * n
    done_b = [False] * n
    best = INF
    while pf and pb:
        d, u = heapq.heappop(pf)
        if d != df[u]:
            continue
        done_f[u] = True
        if done_b[u]:
            best = min(best, df[u] + db[u])
        for v, w in adj[u]:
            if df[u] + w < df[v]:
                df[v] = df[u] + w
                heapq.heappush(pf, (df[v], v))
        d, u = heapq.heappop(pb)
        if d != db[u]:
            continue
        done_b[u] = True
        if done_f[u]:
            best = min(best, df[u] + db[u])
        for v, w in radj[u]:
            if db[u] + w < db[v]:
                db[v] = db[u] + w
                heapq.heappush(pb, (db[v], v))
        if pf and pb and pf[0][0] + pb[0][0] >= best:
            break
    return best

def main() -> None:
    adj = [[(1, 4), (2, 1)], [(2, 2), (3, 5)], [(3, 1)], []]
    assert bidir_dijkstra(4, adj, 0, 3) == 2
    assert bidir_dijkstra(4, adj, 0, 0) == 0
    line = [[(1, 1)], [(0, 1), (2, 1)], [(1, 1), (3, 1)], [(2, 1)]]
    assert bidir_dijkstra(4, line, 0, 3) == 3
    adj2 = [[(1, 1)], [], [], []]
    assert bidir_dijkstra(4, adj2, 0, 3) == INF
    assert stdlib_only()
    print("sp-08 OK")

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
