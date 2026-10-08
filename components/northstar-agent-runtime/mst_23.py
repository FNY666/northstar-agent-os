"""Boruvka deterministic tie-break by edge index (MST-023), Real."""
from __future__ import annotations
import ast

VERSION = "mst-23.v1"

def boruvka_tiebreak(n, edges):
    ed = [(u, v, w) for u, v, w in edges if u != v]
    parent = list(range(n))
    rank = [0] * n
    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x
    mst = []
    while True:
        cheapest = {}
        for idx, (u, v, w) in enumerate(ed):
            ru, rv = find(u), find(v)
            if ru == rv:
                continue
            cand = (w, idx, u, v)
            if ru not in cheapest or cand < cheapest[ru]:
                cheapest[ru] = cand
            if rv not in cheapest or cand < cheapest[rv]:
                cheapest[rv] = cand
        if not cheapest:
            break
        progress = False
        for w, idx, u, v in cheapest.values():
            ru, rv = find(u), find(v)
            if ru == rv:
                continue
            if rank[ru] < rank[rv]:
                parent[ru] = rv
            elif rank[ru] > rank[rv]:
                parent[rv] = ru
            else:
                parent[rv] = ru
                rank[ru] += 1
            mst.append((u, v, w))
            progress = True
        if not progress:
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
    t1, m1 = boruvka_tiebreak(4, e)
    t2, m2 = boruvka_tiebreak(4, list(e))
    assert t1 == t2 == 3 and m1 == m2  # deterministic on identical input
    t3, m3 = boruvka_tiebreak(4, list(reversed(e)))
    assert t3 == 3 and len(m3) == 3  # permutation still yields an MST
    t, m = boruvka_tiebreak(3, [(0, 1, 1), (1, 2, 2), (0, 2, 3)])
    assert t == 3
    assert stdlib_only()
    print("mst-23 OK")


if __name__ == "__main__":
    main()
