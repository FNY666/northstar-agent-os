"""Kruskal deterministic tie-break (stable output) (MST-008), Real."""
from __future__ import annotations
import ast

VERSION = "mst-08.v1"

def kruskal_stable(n, edges):
    parent = list(range(n))
    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x
    mst = []
    key = lambda e: (e[2], min(e[0], e[1]), max(e[0], e[1]))
    for u, v, w in sorted(edges, key=key):
        if u == v:
            continue
        ru, rv = find(u), find(v)
        if ru != rv:
            parent[rv] = ru
            mst.append((u, v, w))
            if len(mst) == n - 1:
                break
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
    e = [(0, 1, 1), (1, 2, 1), (2, 3, 1), (3, 0, 1)]
    t1, m1 = kruskal_stable(4, e)
    t2, m2 = kruskal_stable(4, list(reversed(e)))
    assert m1 == m2 and t1 == 3
    t, m = kruskal_stable(3, [(0, 1, 1), (1, 2, 2), (0, 2, 3)])
    assert t == 3
    assert stdlib_only()
    print("mst-08 OK")


if __name__ == "__main__":
    main()
