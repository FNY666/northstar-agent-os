"""Hamiltonian path SAT encoding mock (HAM-047), Mock."""
from __future__ import annotations
import ast

VERSION = "ham-47.v1"

def _adj(n, edges):
    a = [[] for _ in range(n)]
    for u, v in edges:
        a[u].append(v)
        a[v].append(u)
    return a

def ham_sat_encode(n, edges):
    eset = set()
    for u, v in edges:
        eset.add((u, v))
        eset.add((v, u))
    clauses = []
    for p in range(n):
        clauses.append(('exactly-one', [('x', v, p) for v in range(n)]))
    for v in range(n):
        clauses.append(('exactly-one', [('x', v, p) for p in range(n)]))
    for p in range(n - 1):
        for u in range(n):
            for v in range(n):
                if u != v and (u, v) not in eset:
                    clauses.append(('not-both', ('x', u, p), ('x', v, p + 1)))
    return {'vars': n * n, 'clauses': clauses, 'n': n}

def _bt(n, edges):
    adj = _adj(n, edges)
    path = [0] * n
    used = [False] * n
    def dfs(pos):
        if pos == n:
            return True
        cands = adj[path[pos - 1]] if pos else range(n)
        for v in cands:
            if not used[v]:
                used[v] = True
                path[pos] = v
                if dfs(pos + 1):
                    return True
                used[v] = False
        return False
    return list(path) if dfs(0) else []

def _ok(n, edges, path):
    if len(path) != n or len(set(path)) != n:
        return False
    s = set()
    for u, v in edges:
        s.add((u, v))
        s.add((v, u))
    return all((path[i], path[i + 1]) in s for i in range(n - 1))

def ham_sat_solve(n, edges):
    return _bt(n, edges)

def main() -> None:
    tri = [(0, 1), (1, 2), (2, 0)]
    enc = ham_sat_encode(3, tri)
    assert enc['vars'] == 9
    assert len(enc['clauses']) == 6
    assert _ok(3, tri, ham_sat_solve(3, tri))
    assert ham_sat_solve(3, [(0, 1)]) == []
    enc2 = ham_sat_encode(2, [(0, 1)])
    assert enc2['vars'] == 4 and len(enc2['clauses']) == 4
    assert stdlib_only()
    print('ham-47.v1 OK')
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
