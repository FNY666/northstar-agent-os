"""Prim dict-based adjacency (MST-017), Real."""
from __future__ import annotations
import ast
import heapq
VERSION = "mst-17.v1"

def prim_dict(n, edges):
    adj = {i: {} for i in range(n)}
    for u, v, w in edges:
        if u == v:
            continue
        if v not in adj[u] or w < adj[u][v]:
            adj[u][v] = w
            adj[v][u] = w
    visited = set()
    heap = [(0, 0, -1)]
    mst = []
    while heap:
        w, u, p = heapq.heappop(heap)
        if u in visited:
            continue
        visited.add(u)
        if p != -1:
            mst.append((p, u, w))
        for v, w2 in adj[u].items():
            if v not in visited:
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
    t, m = prim_dict(3, [(0, 1, 1), (1, 2, 2), (0, 2, 3)])
    assert t == 3 and len(m) == 2
    t, m = prim_dict(3, [(0, 1, 9), (0, 1, 2), (1, 2, 1)])
    assert t == 3  # parallel edge keeps min
    t, m = prim_dict(1, [])
    assert t == 0 and m == []
    assert stdlib_only()
    print("mst-17 OK")


if __name__ == "__main__":
    main()
