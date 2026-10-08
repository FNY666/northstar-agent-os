"""Edge fixed Hamiltonian cycle (HAM-039), Real."""
from __future__ import annotations
import ast

VERSION = "ham-39.v1"

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

def _path_fixed(n, edges, s, t):
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

def ham_cycle_with_edge(n, edges, fixed):
    a, b = fixed
    eset = set()
    for u, v in edges:
        eset.add((u, v))
        eset.add((v, u))
    if (a, b) not in eset:
        return []
    return _path_fixed(n, edges, b, a)

def main() -> None:
    sq = [(0, 1), (1, 2), (2, 3), (3, 0)]
    c = ham_cycle_with_edge(4, sq, (0, 1))
    assert _okc(4, sq, c)
    pairs = {(c[i], c[(i + 1) % 4]) for i in range(4)}
    assert (0, 1) in pairs or (1, 0) in pairs
    assert ham_cycle_with_edge(4, sq, (0, 2)) == []
    k4 = [(i, j) for i in range(4) for j in range(i + 1, 4)]
    c2 = ham_cycle_with_edge(4, k4, (2, 3))
    assert _okc(4, k4, c2)
    assert ham_cycle_with_edge(0, [], (0, 1)) == []
    assert stdlib_only()
    print('ham-39.v1 OK')
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
