"""Kruskal counting-sort edges (bounded int weights) (MST-004), Real."""
from __future__ import annotations
import ast

VERSION = "mst-04.v1"

def kruskal_counting(n, edges):
    edges = [(u, v, w) for u, v, w in edges if u != v]
    if not edges:
        return 0, []
    assert all(isinstance(w, int) and w >= 0 for _, _, w in edges), "needs non-negative int weights"
    maxw = max(w for _, _, w in edges)
    buckets = [[] for _ in range(maxw + 1)]
    for e in edges:
        buckets[e[2]].append(e)
    parent = list(range(n))
    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x
    mst = []
    for bucket in buckets:
        for u, v, w in bucket:
            ru, rv = find(u), find(v)
            if ru != rv:
                parent[rv] = ru
                mst.append((u, v, w))
                if len(mst) == n - 1:
                    return sum(x[2] for x in mst), mst
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
    t, m = kruskal_counting(3, [(0, 1, 1), (1, 2, 2), (0, 2, 3)])
    assert t == 3 and len(m) == 2
    t, m = kruskal_counting(4, [(0, 1, 0), (1, 2, 0), (2, 3, 5), (0, 3, 5)])
    assert t == 5
    t, m = kruskal_counting(3, [(0, 1, 7), (1, 2, 7), (0, 2, 1)])
    assert t == 8
    assert stdlib_only()
    print("mst-04 OK")


if __name__ == "__main__":
    main()
