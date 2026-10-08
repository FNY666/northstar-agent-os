"""Lexicographically smallest canonical MST (MST-050), Real."""
from __future__ import annotations
import ast

VERSION = "mst-50.v1"

def mst_lexicographic(n, edges):
    # Deterministic canonical MST: Kruskal over edges sorted by
    # (weight, u, v) yields the lexicographically smallest edge list
    # among the MSTs reachable by this tie-breaking discipline.
    parent = list(range(n))
    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x
    norm = []
    for u, v, w in edges:
        if u == v:
            continue
        a, b = (u, v) if u < v else (v, u)
        norm.append((w, a, b))
    norm.sort()
    mst = []
    for w, a, b in norm:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[rb] = ra
            mst.append((a, b, w))
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
    e = [(0, 1, 1), (1, 2, 1), (2, 3, 1), (3, 0, 1)]
    t1, m1 = mst_lexicographic(4, e)
    t2, m2 = mst_lexicographic(4, list(reversed(e)))
    assert m1 == m2 and t1 == 3
    assert m1 == sorted(m1)
    t, m = mst_lexicographic(3, [(0, 1, 1), (1, 2, 2), (0, 2, 3)])
    assert t == 3 and m == [(0, 1, 1), (1, 2, 2)]
    assert stdlib_only()
    print("mst-50 OK")


if __name__ == "__main__":
    main()
