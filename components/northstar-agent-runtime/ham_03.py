"""Backtracking Hamiltonian path directed (HAM-003), Real."""
from __future__ import annotations
import ast

VERSION = "ham-03.v1"

def _dadj(n, edges):
    a = [[] for _ in range(n)]
    for u, v in edges:
        a[u].append(v)
    return a

def _dok(n, edges, path):
    if len(path) != n or len(set(path)) != n:
        return False
    s = set(edges)
    return all((path[i], path[i + 1]) in s for i in range(n - 1))

def hamiltonian_path_d(n, edges):
    adj = _dadj(n, edges)
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
    e = [(0, 1), (1, 2), (0, 2)]
    assert _dok(3, e, hamiltonian_path_d(3, e))
    assert hamiltonian_path_d(3, [(0, 1), (2, 1)]) == []
    cyc = [(0, 1), (1, 2), (2, 0)]
    assert _dok(3, cyc, hamiltonian_path_d(3, cyc))
    assert hamiltonian_path_d(0, []) == []
    assert _dok(1, [], hamiltonian_path_d(1, []))
    assert stdlib_only()
    print('ham-03.v1 OK')
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
