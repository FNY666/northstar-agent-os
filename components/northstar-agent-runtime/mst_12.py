"""Prim binary-heap lazy (heapq, adjacency list) (MST-012), Real."""
from __future__ import annotations
import ast
import heapq
VERSION = "mst-12.v1"

def prim_heap(n, edges):
    adj = [[] for _ in range(n)]
    for u, v, w in edges:
        if u == v:
            continue
        adj[u].append((w, v))
        adj[v].append((w, u))
    visited = [False] * n
    heap = [(0, 0, -1)]
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
    t, m = prim_heap(3, [(0, 1, 1), (1, 2, 2), (0, 2, 3)])
    assert t == 3 and len(m) == 2
    t, m = prim_heap(4, [(0, 1, 1), (1, 2, 1), (2, 3, 1), (3, 0, 1), (0, 2, 2)])
    assert t == 3
    t, m = prim_heap(5, [(0, 1, 2), (0, 2, 3), (1, 2, 1), (1, 3, 4), (2, 4, 5), (3, 4, 1)])
    assert t == 8, t
    assert stdlib_only()
    print("mst-12 OK")


if __name__ == "__main__":
    main()
