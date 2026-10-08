"""Iterative deepening DFS Hamiltonian path (HAM-049), Real."""
from __future__ import annotations
import ast

VERSION = "ham-49.v1"

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

def _dls(adj, n, s, limit):
    path = [s]
    used = {s}
    def rec():
        if len(path) == limit:
            return list(path) if limit == n else None
        for v in adj[path[-1]]:
            if v not in used:
                used.add(v)
                path.append(v)
                r = rec()
                if r:
                    return r
                path.pop()
                used.remove(v)
        return None
    return rec()

def ham_path_iddfs(n, edges):
    adj = _adj(n, edges)
    for limit in range(1, n + 1):
        for s in range(n):
            r = _dls(adj, n, s, limit)
            if r:
                return r
    return []

def main() -> None:
    p4 = [(0, 1), (1, 2), (2, 3)]
    assert _ok(4, p4, ham_path_iddfs(4, p4))
    k3 = [(0, 1), (1, 2), (0, 2)]
    assert _ok(3, k3, ham_path_iddfs(3, k3))
    assert ham_path_iddfs(4, [(0, 1), (2, 3)]) == []
    assert ham_path_iddfs(0, []) == []
    assert _ok(1, [], ham_path_iddfs(1, []))
    assert stdlib_only()
    print('ham-49.v1 OK')
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
