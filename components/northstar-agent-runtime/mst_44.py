"""Karger-Klein-Tarjan randomized (Kruskal fallback) (MST-044), Simulated."""
from __future__ import annotations
import ast

VERSION = "mst-44.v1"

def kkt_mock(n, edges, seed=0):
    # Karger-Klein-Tarjan is a randomized linear-expected-time MST
    # algorithm. Its Boruvka phases plus random sampling need a verified
    # MST verification subroutine; this module documents the algorithm and
    # falls back to Kruskal for the actual edge set (simulated).
    import random
    rng = random.Random(seed)
    sampled = [e for e in edges if rng.random() < 0.5]
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
    return sum(x[2] for x in mst), mst, len(sampled)

def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib", "typing", "heapq", "collections", "math", "itertools", "functools", "random"}
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
    t, m, s = kkt_mock(3, [(0, 1, 1), (1, 2, 2), (0, 2, 3)], seed=1)
    assert t == 3 and len(m) == 2
    t, m, s = kkt_mock(4, [(0, 1, 1), (1, 2, 1), (2, 3, 1), (3, 0, 1), (0, 2, 2)], seed=7)
    assert t == 3
    assert stdlib_only()
    print("mst-44 OK")


if __name__ == "__main__":
    main()
