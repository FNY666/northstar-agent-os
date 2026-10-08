"""Karger randomized min cut (FLOW-023), Real."""
from __future__ import annotations
import ast

VERSION = "flow-23.v1"

def min_cut(n, edges, trials=300):
    import random
    best = None
    for _ in range(trials):
        parent = list(range(n))
        def find(x):
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x
        verts = n
        el = list(edges)
        while verts > 2:
            u, v = random.choice(el)
            ru, rv = find(u), find(v)
            if ru == rv:
                continue
            parent[ru] = rv
            verts -= 1
        cut = sum(1 for u, v in el if find(u) != find(v))
        if best is None or cut < best:
            best = cut
    return best

def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib", "typing", "heapq", "collections",
               "math", "itertools", "functools", "random", "sys", "copy"}
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
    assert min_cut(3, [(0,1),(1,2),(2,0)]) == 2
    assert min_cut(4, [(0,1),(1,2),(2,3),(3,0)]) == 2
    assert min_cut(2, [(0,1),(0,1)]) == 2
    assert stdlib_only()
    print("flow-23 OK")


if __name__ == "__main__":
    main()
