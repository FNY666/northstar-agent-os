"""Yen's K shortest loopless paths (simplified) (SP-049), Real."""
from __future__ import annotations
import ast

VERSION = "sp-49.v1"

import heapq
INF = float("inf")

def _dijkstra_path(n, adj, src, dst, banned_nodes, banned_edges):
    dist = [INF] * n
    parent = [-1] * n
    dist[src] = 0
    pq = [(0, src)]
    while pq:
        d, u = heapq.heappop(pq)
        if d != dist[u]:
            continue
        if u == dst:
            break
        for v, w in adj[u]:
            if v in banned_nodes or (u, v) in banned_edges:
                continue
            nd = d + w
            if nd < dist[v]:
                dist[v] = nd
                parent[v] = u
                heapq.heappush(pq, (nd, v))
    if dist[dst] == INF:
        return None
    path = []
    cur = dst
    while cur != -1:
        path.append(cur)
        cur = parent[cur]
    path.reverse()
    return dist[dst], path

def _cost(adj, path):
    wmap = {}
    for u in range(len(adj)):
        for v, w in adj[u]:
            wmap[(u, v)] = w
    return sum(wmap[(path[i], path[i + 1])] for i in range(len(path) - 1))

def yens_k(n, adj, src, dst, k):
    first = _dijkstra_path(n, adj, src, dst, set(), set())
    if first is None:
        return []
    paths = [first[1]]
    costs = [first[0]]
    cands = []
    seen = {tuple(first[1])}
    for _ in range(1, k):
        prev = paths[-1]
        for i in range(len(prev) - 1):
            spur = prev[i]
            root = prev[:i + 1]
            banned_e = set()
            banned_n = set(root[:-1])
            for p in paths:
                if len(p) > i and p[:i + 1] == root:
                    banned_e.add((p[i], p[i + 1]))
            sp = _dijkstra_path(n, adj, spur, dst, banned_n, banned_e)
            if sp is not None:
                total = root[:-1] + sp[1]
                t = tuple(total)
                if t not in seen:
                    seen.add(t)
                    heapq.heappush(cands, (_cost(adj, root) + sp[0], total))
        if not cands:
            break
        c, p = heapq.heappop(cands)
        paths.append(p)
        costs.append(c)
    return list(zip(costs, paths))

def main() -> None:
    adj = [[(1, 1), (2, 2)], [(3, 1)], [(3, 1)], []]
    r = yens_k(4, adj, 0, 3, 2)
    assert len(r) == 2 and r[0][0] == 2 and r[1][0] == 3
    assert r[0][1] == [0, 1, 3] and r[1][1] == [0, 2, 3]
    r1 = yens_k(4, adj, 0, 3, 1)
    assert len(r1) == 1
    assert yens_k(3, [[(1, 1)], [], []], 0, 2, 2) == []
    r3 = yens_k(1, [[]], 0, 0, 2)
    assert len(r3) == 1 and r3[0][0] == 0
    assert stdlib_only()
    print("sp-49 OK")

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
