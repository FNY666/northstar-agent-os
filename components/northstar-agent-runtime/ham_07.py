"""Backtracking Hamiltonian path with degree pruning (HAM-007), Real."""
from __future__ import annotations
import ast

VERSION = "ham-07.v1"

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

def hamiltonian_path_prune(n, edges):
    adj = _adj(n, edges)
    path = [0] * n
    used = [False] * n
    def viable(pos):
        rem = n - pos
        for v in range(n):
            if not used[v]:
                if rem == 1:
                    continue
                if not any(not used[w] for w in adj[v]):
                    return False
        return True
    def dfs(pos):
        if pos == n:
            return True
        if not viable(pos):
            return False
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
    k5 = [(i, j) for i in range(5) for j in range(i + 1, 5)]
    assert _ok(5, k5, hamiltonian_path_prune(5, k5))
    p5 = [(i, i + 1) for i in range(4)]
    assert _ok(5, p5, hamiltonian_path_prune(5, p5))
    star = [(0, 1), (0, 2), (0, 3)]
    assert hamiltonian_path_prune(4, star) == []
    assert hamiltonian_path_prune(4, [(0, 1), (2, 3)]) == []
    assert hamiltonian_path_prune(0, []) == []
    assert stdlib_only()
    print('ham-07.v1 OK')
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
