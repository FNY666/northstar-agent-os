"""Prim eager decrease-key simulation (MST-013), Real."""
from __future__ import annotations
import ast
import heapq
VERSION = "mst-13.v1"

def prim_eager(n, edges):
    adj = [[] for _ in range(n)]
    for u, v, w in edges:
        if u == v:
            continue
        adj[u].append((v, w))
        adj[v].append((u, w))
    INF = float("inf")
    best = [INF] * n
    in_mst = [False] * n
    par = [-1] * n
    best[0] = 0
    heap = [(0, 0)]
    mst = []
    while heap:
        w, u = heapq.heappop(heap)
        if in_mst[u] or w > best[u]:
            continue
        in_mst[u] = True
        if par[u] != -1:
            mst.append((par[u], u, w))
        for v, w2 in adj[u]:
            if not in_mst[v] and w2 < best[v]:
                best[v] = w2
                par[v] = u
                heapq.heappush(heap, (w2, v))
    return sum(x[2] for x in mst), mst

def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib", "typing", "heapq", "collections", "math", "itertools", "functools"}
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                if a.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(n, ast.ImportFrom):
            if n.module and n.module.split(".")[0] not in allowed:
                return False
    return True

def main() -> None:
    t, m = prim_eager(3, [(0, 1, 1), (1, 2, 2), (0, 2, 3)])
    assert t == 3 and len(m) == 2
    t, m = prim_eager(4, [(0, 1, 1), (1, 2, 1), (2, 3, 1), (3, 0, 1), (0, 2, 2)])
    assert t == 3
    t, m = prim_eager(3, [(0, 1, 10), (1, 2, 1), (0, 2, 1)])
    assert t == 2
    assert stdlib_only()
    print("mst-13 OK")


if __name__ == "__main__":
    main()
