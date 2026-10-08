"""Complement graph Hamiltonian path (HAM-036), Real."""
from __future__ import annotations
import ast

VERSION = "ham-36.v1"

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

def ham_path_complement(n, edges):
    eset = set()
    for u, v in edges:
        eset.add((u, v))
        eset.add((v, u))
    comp = [(u, v) for u in range(n) for v in range(u + 1, n) if (u, v) not in eset]
    p = _bt(n, comp)
    if p and _ok(n, comp, p):
        return p
    return []

def main() -> None:
    p = ham_path_complement(4, [])
    assert len(p) == 4 and len(set(p)) == 4
    star = [(0, 1), (0, 2), (0, 3)]
    assert ham_path_complement(4, star) == []
    k3 = [(0, 1), (1, 2), (0, 2)]
    assert ham_path_complement(3, k3) == []
    assert ham_path_complement(0, []) == []
    p2 = ham_path_complement(2, [])
    assert p2 == [0, 1] or p2 == [1, 0]
    assert stdlib_only()
    print('ham-36.v1 OK')
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
