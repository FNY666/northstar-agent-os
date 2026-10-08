"""Bidirectional two ended Hamiltonian path search (HAM-048), Real."""
from __future__ import annotations
import ast

VERSION = "ham-48.v1"

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

def _dfs2(path, used, adj, n):
    from collections import deque
    if len(path) == n:
        return list(path)
    left, right = path[0], path[-1]
    ends = [(left, True)] if left == right else [(left, True), (right, False)]
    ends.sort(key=lambda e: sum(1 for v in adj[e[0]] if v not in used))
    for end, is_left in ends:
        for v in adj[end]:
            if v not in used:
                used.add(v)
                if is_left:
                    path.appendleft(v)
                else:
                    path.append(v)
                r = _dfs2(path, used, adj, n)
                if r:
                    return r
                if is_left:
                    path.popleft()
                else:
                    path.pop()
                used.remove(v)
    return None

def ham_path_bidirectional(n, edges):
    from collections import deque
    adj = _adj(n, edges)
    for s in range(n):
        r = _dfs2(deque([s]), {s}, adj, n)
        if r:
            return r
    return []

def main() -> None:
    k4 = [(i, j) for i in range(4) for j in range(i + 1, 4)]
    assert _ok(4, k4, ham_path_bidirectional(4, k4))
    p4 = [(0, 1), (1, 2), (2, 3)]
    assert _ok(4, p4, ham_path_bidirectional(4, p4))
    assert ham_path_bidirectional(4, [(0, 1), (2, 3)]) == []
    assert ham_path_bidirectional(0, []) == []
    assert _ok(1, [], ham_path_bidirectional(1, []))
    assert stdlib_only()
    print('ham-48.v1 OK')
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
