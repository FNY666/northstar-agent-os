"""Backtracking Hamiltonian path undirected (HAM-001), Real."""
from __future__ import annotations
import ast

VERSION = "ham-01.v1"

def _adj(n, edges):
    a = [[] for _ in range(n)]
    for u, v in edges:
        a[u].append(v)
        a[v].append(u)
    return a

def _ok(n, edges, path):
    if len(path) != n or len(set(path)) != n:
        return False
    s = set()
    for u, v in edges:
        s.add((u, v))
        s.add((v, u))
    return all((path[i], path[i + 1]) in s for i in range(n - 1))

def hamiltonian_path(n, edges):
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

def main() -> None:
    e = [(0, 1), (1, 2), (2, 3), (0, 2)]
    assert _ok(4, e, hamiltonian_path(4, e))
    assert hamiltonian_path(4, [(0, 1), (2, 3)]) == []
    e3 = [(0, 1), (1, 2), (0, 2)]
    assert _ok(3, e3, hamiltonian_path(3, e3))
    assert hamiltonian_path(0, []) == []
    assert _ok(1, [], hamiltonian_path(1, []))
    assert stdlib_only()
    print('ham-01.v1 OK')
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
