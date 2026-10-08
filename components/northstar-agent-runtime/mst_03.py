"""Kruskal union by size (MST-003), Real."""
from __future__ import annotations
import ast

VERSION = "mst-03.v1"

def kruskal_size(n, edges):
    parent = list(range(n))
    size = [1] * n
    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x
    def union(a, b):
        ra, rb = find(a), find(b)
        if ra == rb:
            return False
        if size[ra] < size[rb]:
            ra, rb = rb, ra
        parent[rb] = ra
        size[ra] += size[rb]
        return True
    mst = []
    for u, v, w in sorted(edges, key=lambda e: e[2]):
        if u == v:
            continue
        if union(u, v):
            mst.append((u, v, w))
            if len(mst) == n - 1:
                break
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
    t, m = kruskal_size(3, [(0, 1, 1), (1, 2, 2), (0, 2, 3)])
    assert t == 3 and len(m) == 2
    t, m = kruskal_size(4, [(0, 1, 1), (1, 2, 1), (2, 3, 1), (3, 0, 1), (0, 2, 2)])
    assert t == 3
    t, m = kruskal_size(2, [(0, 1, 9)])
    assert t == 9 and len(m) == 1
    assert stdlib_only()
    print("mst-03 OK")


if __name__ == "__main__":
    main()
