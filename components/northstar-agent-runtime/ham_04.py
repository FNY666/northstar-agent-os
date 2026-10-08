"""Backtracking Hamiltonian circuit directed (HAM-004), Real."""
from __future__ import annotations
import ast

VERSION = "ham-04.v1"

def _dadj(n, edges):
    a = [[] for _ in range(n)]
    for u, v in edges:
        a[u].append(v)
    return a

def _dokc(n, edges, path):
    if len(path) != n or len(set(path)) != n:
        return False
    s = set(edges)
    c = path + [path[0]]
    return all((c[i], c[i + 1]) in s for i in range(n))

def hamiltonian_circuit_d(n, edges):
    if n == 0:
        return []
    adj = _dadj(n, edges)
    path = [0] * n
    used = [False] * n
    used[0] = True
    path[0] = 0
    eset = set(edges)
    def dfs(pos):
        if pos == n:
            return (path[n - 1], 0) in eset
        for v in adj[path[pos - 1]]:
            if not used[v]:
                used[v] = True
                path[pos] = v
                if dfs(pos + 1):
                    return True
                used[v] = False
        return False
    return list(path) if dfs(1) else []

def main() -> None:
    tri = [(0, 1), (1, 2), (2, 0)]
    assert _dokc(3, tri, hamiltonian_circuit_d(3, tri))
    assert hamiltonian_circuit_d(3, [(0, 1), (1, 2)]) == []
    k4 = [(i, j) for i in range(4) for j in range(4) if i != j]
    assert _dokc(4, k4, hamiltonian_circuit_d(4, k4))
    assert hamiltonian_circuit_d(0, []) == []
    assert hamiltonian_circuit_d(2, [(0, 1)]) == []
    assert stdlib_only()
    print('ham-04.v1 OK')
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
