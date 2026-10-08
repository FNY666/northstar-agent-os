"""Prim dense O(V^2) with adjacency list scan (MST-014), Real."""
from __future__ import annotations
import ast

VERSION = "mst-14.v1"

def prim_dense(n, edges):
    adj = [[] for _ in range(n)]
    for u, v, w in edges:
        if u == v:
            continue
        adj[u].append((v, w))
        adj[v].append((u, w))
    INF = float("inf")
    in_mst = [False] * n
    key = [INF] * n
    par = [-1] * n
    key[0] = 0
    mst = []
    for _ in range(n):
        u = -1
        bk = INF
        for i in range(n):
            if not in_mst[i] and key[i] < bk:
                bk = key[i]
                u = i
        if u == -1:
            break
        in_mst[u] = True
        if par[u] != -1:
            mst.append((par[u], u, bk))
        for v, w in adj[u]:
            if not in_mst[v] and w < key[v]:
                key[v] = w
                par[v] = u
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
    t, m = prim_dense(3, [(0, 1, 1), (1, 2, 2), (0, 2, 3)])
    assert t == 3 and len(m) == 2
    t, m = prim_dense(4, [(0, 1, 1), (1, 2, 1), (2, 3, 1), (3, 0, 1), (0, 2, 2)])
    assert t == 3
    t, m = prim_dense(4, [(0, 1, 4), (0, 2, 3), (0, 3, 2), (1, 2, 5), (2, 3, 1)])
    assert t == 7, t  # (2,3,1)+(0,3,2)+(0,1,4)
    assert stdlib_only()
    print("mst-14 OK")


if __name__ == "__main__":
    main()
