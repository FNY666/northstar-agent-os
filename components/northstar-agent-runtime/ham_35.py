"""Petersen graph non Hamiltonian proof (HAM-035), Real."""
from __future__ import annotations
import ast

VERSION = "ham-35.v1"

def _adj(n, edges):
    a = [[] for _ in range(n)]
    for u, v in edges:
        a[u].append(v)
        a[v].append(u)
    return a

def petersen_edges():
    e = []
    for i in range(5):
        e.append((i, (i + 1) % 5))
        e.append((5 + i, 5 + ((i + 2) % 5)))
        e.append((i, 5 + i))
    return e

def _has_circuit(n, edges):
    adj = _adj(n, edges)
    path = [0]
    used = {0}
    nbr0 = set(adj[0])
    def conn():
        unvis = [v for v in range(n) if v not in used]
        if len(unvis) <= 1:
            return True
        seen = {unvis[0]}
        stack = [unvis[0]]
        while stack:
            u = stack.pop()
            for w in adj[u]:
                if w not in used and w not in seen:
                    seen.add(w)
                    stack.append(w)
        return len(seen) == len(unvis)
    def dfs():
        if len(path) == n:
            return path[-1] in nbr0
        if not conn():
            return False
        for v in adj[path[-1]]:
            if v not in used:
                used.add(v)
                path.append(v)
                if dfs():
                    return True
                path.pop()
                used.remove(v)
        return False
    return dfs()

def _bt_path(n, edges, s):
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
    return dfs()

def _has_path(n, edges):
    return any(_bt_path(n, edges, s) for s in range(n))

def main() -> None:
    e = petersen_edges()
    assert len(e) == 15
    assert _has_circuit(10, e) is False
    assert _has_path(10, e) is True
    assert _has_circuit(3, [(0, 1), (1, 2), (2, 0)]) is True
    assert _has_path(3, [(0, 1)]) is False
    assert stdlib_only()
    print('ham-35.v1 OK')
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
