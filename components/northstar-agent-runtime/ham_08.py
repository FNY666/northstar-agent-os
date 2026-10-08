"""Backtracking Hamiltonian path with connectivity pruning (HAM-008), Real."""
from __future__ import annotations
import ast

VERSION = "ham-08.v1"

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

def hamiltonian_path_conn(n, edges):
    adj = _adj(n, edges)
    path = [0] * n
    used = [False] * n
    def connected():
        unvis = [v for v in range(n) if not used[v]]
        if len(unvis) <= 1:
            return True
        seen = {unvis[0]}
        stack = [unvis[0]]
        while stack:
            u = stack.pop()
            for w in adj[u]:
                if not used[w] and w not in seen:
                    seen.add(w)
                    stack.append(w)
        return len(seen) == len(unvis)
    def dfs(pos):
        if pos == n:
            return True
        if not connected():
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
    k4 = [(i, j) for i in range(4) for j in range(i + 1, 4)]
    assert _ok(4, k4, hamiltonian_path_conn(4, k4))
    bridge = [(0, 1), (1, 2), (2, 0), (2, 3), (3, 4), (4, 5), (5, 3)]
    assert _ok(6, bridge, hamiltonian_path_conn(6, bridge))
    assert hamiltonian_path_conn(4, [(0, 1), (2, 3)]) == []
    assert hamiltonian_path_conn(0, []) == []
    assert _ok(1, [], hamiltonian_path_conn(1, []))
    assert stdlib_only()
    print('ham-08.v1 OK')
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
