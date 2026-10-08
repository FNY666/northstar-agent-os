"""Complete bipartite Hamiltonian path constructive (HAM-041), Real."""
from __future__ import annotations
import ast

VERSION = "ham-41.v1"

def complete_bipartite_path(m, n):
    if abs(m - n) > 1:
        return []
    X = list(range(m))
    Y = list(range(m, m + n))
    path = []
    if m >= n:
        for i in range(n):
            path.append(X[i])
            path.append(Y[i])
        if m > n:
            path.append(X[n])
    else:
        for i in range(m):
            path.append(Y[i])
            path.append(X[i])
        path.append(Y[m])
    return path

def complete_bipartite_edges(m, n):
    return [(x, m + y) for x in range(m) for y in range(n)]

def _okg(edges, path):
    if len(set(path)) != len(path):
        return False
    verts = set()
    for u, v in edges:
        verts.add(u)
        verts.add(v)
    if set(path) != verts:
        return False
    s = set()
    for u, v in edges:
        s.add((u, v))
        s.add((v, u))
    return all((path[i], path[i + 1]) in s for i in range(len(path) - 1))

def main() -> None:
    assert _okg(complete_bipartite_edges(2, 2), complete_bipartite_path(2, 2))
    assert _okg(complete_bipartite_edges(3, 2), complete_bipartite_path(3, 2))
    assert _okg(complete_bipartite_edges(2, 3), complete_bipartite_path(2, 3))
    assert complete_bipartite_path(3, 1) == []
    assert _okg(complete_bipartite_edges(4, 4), complete_bipartite_path(4, 4))
    assert stdlib_only()
    print('ham-41.v1 OK')
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
