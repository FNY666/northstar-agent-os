"""Tree Hamiltonian path check (HAM-029), Real."""
from __future__ import annotations
import ast

VERSION = "ham-29.v1"

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

def tree_ham_path(n, edges):
    if n == 0:
        return []
    adj = _adj(n, edges)
    if any(len(a) > 2 for a in adj):
        return []
    seen = set()
    stack = [0]
    while stack:
        u = stack.pop()
        if u in seen:
            continue
        seen.add(u)
        stack.extend(adj[u])
    if len(seen) != n:
        return []
    start = next(i for i in range(n) if len(adj[i]) <= 1)
    path = [start]
    prev = -1
    cur = start
    while len(path) < n:
        nxt = [v for v in adj[cur] if v != prev]
        if not nxt:
            break
        prev, cur = cur, nxt[0]
        path.append(cur)
    return path if len(path) == n else []

def main() -> None:
    p4 = [(0, 1), (1, 2), (2, 3)]
    assert _ok(4, p4, tree_ham_path(4, p4))
    star = [(0, 1), (0, 2), (0, 3)]
    assert tree_ham_path(4, star) == []
    assert tree_ham_path(1, []) == [0]
    assert tree_ham_path(0, []) == []
    p6 = [(i, i + 1) for i in range(5)]
    assert _ok(6, p6, tree_ham_path(6, p6))
    assert stdlib_only()
    print('ham-29.v1 OK')
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
