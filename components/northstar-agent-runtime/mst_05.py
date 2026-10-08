"""Kruskal parallel-edge dedup (keep minimum) (MST-005), Real."""
from __future__ import annotations
import ast

VERSION = "mst-05.v1"

def kruskal_parallel(n, edges):
    best = {}
    for u, v, w in edges:
        if u == v:
            continue
        key = (min(u, v), max(u, v))
        if key not in best or w < best[key][2]:
            best[key] = (key[0], key[1], w)
    parent = list(range(n))
    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x
    mst = []
    for u, v, w in sorted(best.values(), key=lambda e: e[2]):
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
    t, m = kruskal_parallel(3, [(0, 1, 5), (0, 1, 2), (1, 2, 4), (1, 2, 9), (0, 2, 3)])
    assert t == 5, t  # (0,1,2) + (0,2,3)
    t, m = kruskal_parallel(2, [(0, 1, 8), (0, 1, 8), (1, 0, 3)])
    assert t == 3 and len(m) == 1
    t, m = kruskal_parallel(3, [(0, 1, 1), (1, 2, 2), (0, 2, 3)])
    assert t == 3
    assert stdlib_only()
    print("mst-05 OK")


if __name__ == "__main__":
    main()
