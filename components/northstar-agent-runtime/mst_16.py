"""Prim parameterized start vertex (MST-016), Real."""
from __future__ import annotations
import ast
import heapq
VERSION = "mst-16.v1"

def prim_start(n, edges, start=0):
    adj = [[] for _ in range(n)]
    for u, v, w in edges:
        if u == v:
            continue
        adj[u].append((w, v))
        adj[v].append((w, u))
    visited = [False] * n
    heap = [(0, start, -1)]
    mst = []
    while heap:
        w, u, p = heapq.heappop(heap)
        if visited[u]:
            continue
        visited[u] = True
        if p != -1:
            mst.append((p, u, w))
        for w2, v in adj[u]:
            if not visited[v]:
                heapq.heappush(heap, (w2, v, u))
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
    e = [(0, 1, 1), (1, 2, 2), (0, 2, 3)]
    t0, _ = prim_start(3, e, start=0)
    t1, _ = prim_start(3, e, start=1)
    t2, _ = prim_start(3, e, start=2)
    assert t0 == t1 == t2 == 3
    t, m = prim_start(4, [(0, 1, 1), (1, 2, 1), (2, 3, 1), (3, 0, 1)], start=3)
    assert t == 3 and len(m) == 3
    assert stdlib_only()
    print("mst-16 OK")


if __name__ == "__main__":
    main()
