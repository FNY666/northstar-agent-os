"""Memoized DFS Hamiltonian path (HAM-038), Real."""
from __future__ import annotations
import ast

VERSION = "ham-38.v1"

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

def hamiltonian_path_memo(n, edges):
    import functools
    adj = _adj(n, edges)
    adjt = tuple(tuple(sorted(a)) for a in adj)
    full = (1 << n) - 1
    @functools.lru_cache(maxsize=None)
    def can(mask, last):
        if mask == full:
            return True
        for v in adjt[last]:
            if not (mask >> v) & 1 and can(mask | (1 << v), v):
                return True
        return False
    for s in range(n):
        if can(1 << s, s):
            path = [s]
            mask = 1 << s
            last = s
            while mask != full:
                for v in adjt[last]:
                    if not (mask >> v) & 1 and can(mask | (1 << v), v):
                        path.append(v)
                        mask |= (1 << v)
                        last = v
                        break
            return path
    return []

def main() -> None:
    k5 = [(i, j) for i in range(5) for j in range(i + 1, 5)]
    assert _ok(5, k5, hamiltonian_path_memo(5, k5))
    p5 = [(i, i + 1) for i in range(4)]
    assert _ok(5, p5, hamiltonian_path_memo(5, p5))
    assert hamiltonian_path_memo(4, [(0, 1), (2, 3)]) == []
    assert hamiltonian_path_memo(0, []) == []
    assert _ok(1, [], hamiltonian_path_memo(1, []))
    assert stdlib_only()
    print('ham-38.v1 OK')
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
