"""Hamiltonian path with fixed endpoints (HAM-025), Real."""
from __future__ import annotations
import ast

VERSION = "ham-25.v1"

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

def hamiltonian_path_fixed(n, edges, s, t):
    if n == 0:
        return []
    adj = _adj(n, edges)
    path = [s]
    used = {s}
    def dfs():
        if len(path) == n:
            return path[-1] == t
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

def main() -> None:
    sq = [(0, 1), (1, 2), (2, 3), (3, 0)]
    p = hamiltonian_path_fixed(4, sq, 0, 3)
    assert _ok(4, sq, p) and p[0] == 0 and p[-1] == 3
    assert hamiltonian_path_fixed(4, sq, 0, 2) == []
    assert hamiltonian_path_fixed(1, [], 0, 0) == [0]
    k4 = [(i, j) for i in range(4) for j in range(i + 1, 4)]
    p2 = hamiltonian_path_fixed(4, k4, 1, 2)
    assert _ok(4, k4, p2) and p2[0] == 1 and p2[-1] == 2
    assert hamiltonian_path_fixed(0, [], 0, 0) == []
    assert stdlib_only()
    print('ham-25.v1 OK')
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
