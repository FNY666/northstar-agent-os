"""Boruvka basic phases (MST-021), Real."""
from __future__ import annotations
import ast

VERSION = "mst-21.v1"

def boruvka(n, edges):
    comp = list(range(n))
    def find(x):
        while comp[x] != x:
            comp[x] = comp[comp[x]]
            x = comp[x]
        return x
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
            ru, rv = find(u), find(v)
            if ru != rv:
                comp[ru] = rv
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
    t, m = boruvka(3, [(0, 1, 1), (1, 2, 2), (0, 2, 3)])
    assert t == 3 and len(m) == 2
    t, m = boruvka(4, [(0, 1, 1), (1, 2, 1), (2, 3, 1), (3, 0, 1), (0, 2, 2)])
    assert t == 3
    t, m = boruvka(6, [(0, 1, 1), (2, 3, 1), (4, 5, 1), (1, 2, 2), (3, 4, 2), (0, 5, 10)])
    assert t == 7, t
    assert stdlib_only()
    print("mst-21 OK")


if __name__ == "__main__":
    main()
