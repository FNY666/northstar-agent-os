"""Boruvka parallel phases (sequential simulation) (MST-025), Simulated."""
from __future__ import annotations
import ast

VERSION = "mst-25.v1"

def boruvka_parallel_mock(n, edges):
    # In a parallel Boruvka, every component independently finds its
    # cheapest outgoing edge in the same phase. This module simulates
    # those synchronized phases sequentially and records the phase each
    # MST edge was added in. The edge set matches sequential Boruvka.
    parent = list(range(n))
    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x
    ed = [(u, v, w) for u, v, w in edges if u != v]
    mst = []
    phases = []
    phase = 0
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
                parent[ru] = rv
                mst.append((u, v, w))
                phases.append(phase)
                added = True
        if not added:
            break
        phase += 1
    return sum(x[2] for x in mst), mst, phases

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
    t, m, p = boruvka_parallel_mock(3, [(0, 1, 1), (1, 2, 2), (0, 2, 3)])
    assert t == 3 and len(m) == 2 and p[0] == 0
    t, m, p = boruvka_parallel_mock(4, [(0, 1, 1), (1, 2, 1), (2, 3, 1), (3, 0, 1), (0, 2, 2)])
    assert t == 3 and max(p) <= 2
    assert stdlib_only()
    print("mst-25 OK")


if __name__ == "__main__":
    main()
