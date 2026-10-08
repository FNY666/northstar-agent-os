"""Boruvka union-find with rank (MST-022), Real."""
from __future__ import annotations
import ast

VERSION = "mst-22.v1"

def boruvka_uf(n, edges):
    parent = list(range(n))
    rank = [0] * n
    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x
    def union(a, b):
        ra, rb = find(a), find(b)
        if ra == rb:
            return False
        if rank[ra] < rank[rb]:
            parent[ra] = rb
        elif rank[ra] > rank[rb]:
            parent[rb] = ra
        else:
            parent[rb] = ra
            rank[ra] += 1
        return True
    ed = [(u, v, w) for u, v, w in edges if u != v]
    mst = []
    total = 0
    while True:
        cheapest = {}
        for u, v, w in ed:
            ru, rv = find(u), find(v)
            if ru == rv:
                continue
            if ru not in cheapest or w < cheapest[ru][2]:
                cheapest[ru] = (u, v, w)
            if rv not in cheapest or w < cheapest[rv][2]:
                cheapest[rv] = (u, v, w)
        if not cheapest:
            break
        added = False
        for u, v, w in cheapest.values():
            if union(u, v):
                mst.append((u, v, w))
                total += w
                added = True
        if not added:
            break
    return total, mst

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
    t, m = boruvka_uf(3, [(0, 1, 1), (1, 2, 2), (0, 2, 3)])
    assert t == 3 and len(m) == 2
    t, m = boruvka_uf(4, [(0, 1, 1), (1, 2, 1), (2, 3, 1), (3, 0, 1), (0, 2, 2)])
    assert t == 3
    t, m = boruvka_uf(1, [])
    assert t == 0 and m == []
    assert stdlib_only()
    print("mst-22 OK")


if __name__ == "__main__":
    main()
