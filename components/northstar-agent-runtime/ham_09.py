"""Posa rotation heuristic Hamiltonian cycle (HAM-009), Real."""
from __future__ import annotations
import ast

VERSION = "ham-09.v1"

def _adj(n, edges):
    a = [[] for _ in range(n)]
    for u, v in edges:
        a[u].append(v)
        a[v].append(u)
    return a

def _okc(n, edges, path):
    if len(path) != n or len(set(path)) != n:
        return False
    s = set()
    for u, v in edges:
        s.add((u, v))
        s.add((v, u))
    c = path + [path[0]]
    return all((c[i], c[i + 1]) in s for i in range(n))

def posa_ham_cycle(n, edges, rounds=2000):
    import random
    if n == 0:
        return []
    adj = _adj(n, edges)
    eset = set()
    for u, v in edges:
        eset.add((u, v))
        eset.add((v, u))
    rng = random.Random(12345)
    verts = list(range(n))
    rng.shuffle(verts)
    path = [verts[0]]
    used = {verts[0]}
    while True:
        extended = False
        for v in adj[path[-1]]:
            if v not in used:
                used.add(v)
                path.append(v)
                extended = True
                break
        if not extended:
            break
    for _ in range(rounds):
        if len(path) == n and (path[-1], path[0]) in eset:
            return list(path)
        last = path[-1]
        pivots = [i for i in range(len(path) - 1) if (last, path[i]) in eset]
        if not pivots:
            break
        i = rng.choice(pivots)
        path = path[:i + 1] + path[:i:-1]
        for v in adj[path[-1]]:
            if v not in used:
                used.add(v)
                path.append(v)
                break
    if len(path) == n and (path[-1], path[0]) in eset:
        return list(path)
    return []

def main() -> None:
    tri = [(0, 1), (1, 2), (2, 0)]
    assert _okc(3, tri, posa_ham_cycle(3, tri))
    sq = [(0, 1), (1, 2), (2, 3), (3, 0)]
    assert _okc(4, sq, posa_ham_cycle(4, sq))
    k6 = [(i, j) for i in range(6) for j in range(i + 1, 6)]
    assert _okc(6, k6, posa_ham_cycle(6, k6))
    assert posa_ham_cycle(4, [(0, 1), (2, 3)]) == []
    assert posa_ham_cycle(0, []) == []
    assert stdlib_only()
    print('ham-09.v1 OK')
def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib", "typing", "heapq", "collections", "math", "itertools", "functools", "dataclasses", "random"}
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                if a.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(n, ast.ImportFrom):
            if n.module and n.module.split(".")[0] not in allowed:
                return False
    return True


if __name__ == "__main__":
    main()
