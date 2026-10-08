"""Hamiltonian path from every start vertex (HAM-026), Real."""
from __future__ import annotations
import ast

VERSION = "ham-26.v1"

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

def ham_path_from(n, edges, s):
    adj = _adj(n, edges)
    path = [s]
    used = {s}
    def dfs():
        if len(path) == n:
            return True
        for v in adj[path[-1]]:
            if v not in used:
                used.add(v)
                path.append(v)
                if dfs():
                    return True
                path.pop()
                used.remove(v)
        return False
    return list(path) if dfs() else []

def ham_paths_all_starts(n, edges):
    return [ham_path_from(n, edges, s) for s in range(n)]

def main() -> None:
    k3 = [(0, 1), (1, 2), (0, 2)]
    r = ham_paths_all_starts(3, k3)
    assert len(r) == 3 and all(_ok(3, k3, p) for p in r)
    p3 = [(0, 1), (1, 2)]
    r2 = ham_paths_all_starts(3, p3)
    assert _ok(3, p3, r2[0]) and r2[1] == []
    assert ham_paths_all_starts(0, []) == []
    r3 = ham_paths_all_starts(1, [])
    assert r3 == [[0]]
    assert stdlib_only()
    print('ham-26.v1 OK')
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
