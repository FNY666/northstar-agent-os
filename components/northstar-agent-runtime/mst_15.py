"""Prim forest (restart per component) (MST-015), Real."""
from __future__ import annotations
import ast
import heapq
VERSION = "mst-15.v1"

def prim_forest(n, edges):
    adj = [[] for _ in range(n)]
    for u, v, w in edges:
        if u == v:
            continue
        adj[u].append((w, v))
        adj[v].append((w, u))
    visited = [False] * n
    forest = []
    for s in range(n):
        if visited[s]:
            continue
        heap = [(0, s, -1)]
        while heap:
            w, u, p = heapq.heappop(heap)
            if visited[u]:
                continue
            visited[u] = True
            if p != -1:
                forest.append((p, u, w))
            for w2, v in adj[u]:
                if not visited[v]:
                    heapq.heappush(heap, (w2, v, u))
    return sum(x[2] for x in forest), forest

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
    t, f = prim_forest(4, [(0, 1, 5), (2, 3, 7)])
    assert t == 12 and len(f) == 2
    t, f = prim_forest(3, [(0, 1, 1), (1, 2, 2), (0, 2, 3)])
    assert t == 3 and len(f) == 2
    t, f = prim_forest(3, [])
    assert t == 0 and f == []
    assert stdlib_only()
    print("mst-15 OK")


if __name__ == "__main__":
    main()
