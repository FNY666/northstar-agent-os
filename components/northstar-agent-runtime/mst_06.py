"""Kruskal self-loop filtering (counts skipped) (MST-006), Real."""
from __future__ import annotations
import ast

VERSION = "mst-06.v1"

def kruskal_selfloops(n, edges):
    skipped = sum(1 for u, v, _ in edges if u == v)
    parent = list(range(n))
    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x
    mst = []
    for u, v, w in sorted(edges, key=lambda e: e[2]):
        if u == v:
            continue
        ru, rv = find(u), find(v)
        if ru != rv:
            parent[rv] = ru
            mst.append((u, v, w))
            if len(mst) == n - 1:
                break
    return sum(x[2] for x in mst), mst, skipped

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
    t, m, s = kruskal_selfloops(3, [(0, 0, 1), (0, 1, 1), (1, 1, 2), (1, 2, 2), (0, 2, 3)])
    assert t == 3 and len(m) == 2 and s == 2
    t, m, s = kruskal_selfloops(2, [(0, 0, 5), (0, 1, 4)])
    assert t == 4 and s == 1
    t, m, s = kruskal_selfloops(1, [(0, 0, 9)])
    assert t == 0 and m == [] and s == 1
    assert stdlib_only()
    print("mst-06 OK")


if __name__ == "__main__":
    main()
