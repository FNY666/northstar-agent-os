"""Prim naive O(V^2) with adjacency matrix (MST-011), Real."""
from __future__ import annotations
import ast

VERSION = "mst-11.v1"

def prim_naive(n, edges):
    INF = float("inf")
    mat = [[INF] * n for _ in range(n)]
    for u, v, w in edges:
        if u != v and w < mat[u][v]:
            mat[u][v] = mat[v][u] = w
    in_mst = [False] * n
    key = [INF] * n
    par = [-1] * n
    key[0] = 0.0
    mst = []
    for _ in range(n):
        u = -1
        best = INF
        for i in range(n):
            if not in_mst[i] and key[i] < best:
                best = key[i]
                u = i
        if u == -1:
            break
        in_mst[u] = True
        if par[u] != -1:
            mst.append((par[u], u, key[u]))
        for v in range(n):
            if not in_mst[v] and mat[u][v] < key[v]:
                key[v] = mat[u][v]
                par[v] = u
    return sum(w for _, _, w in mst), mst

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
    t, m = prim_naive(3, [(0, 1, 1), (1, 2, 2), (0, 2, 3)])
    assert t == 3 and len(m) == 2
    t, m = prim_naive(4, [(0, 1, 1), (1, 2, 1), (2, 3, 1), (3, 0, 1), (0, 2, 2)])
    assert t == 3
    t, m = prim_naive(1, [])
    assert t == 0 and m == []
    assert stdlib_only()
    print("mst-11 OK")


if __name__ == "__main__":
    main()
