"""Backtracking Hamiltonian circuit undirected (HAM-002), Real."""
from __future__ import annotations
import ast

VERSION = "ham-02.v1"

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

def hamiltonian_circuit(n, edges):
    if n == 0:
        return []
    adj = _adj(n, edges)
    path = [0] * n
    used = [False] * n
    used[0] = True
    path[0] = 0
    nbr0 = set(adj[0])
    def dfs(pos):
        if pos == n:
            return path[n - 1] in nbr0
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
    assert _okc(3, tri, hamiltonian_circuit(3, tri))
    sq = [(0, 1), (1, 2), (2, 3), (3, 0)]
    assert _okc(4, sq, hamiltonian_circuit(4, sq))
    assert hamiltonian_circuit(3, [(0, 1), (1, 2)]) == []
    assert hamiltonian_circuit(0, []) == []
    k4 = [(i, j) for i in range(4) for j in range(i + 1, 4)]
    assert _okc(4, k4, hamiltonian_circuit(4, k4))
    assert stdlib_only()
    print('ham-02.v1 OK')
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
