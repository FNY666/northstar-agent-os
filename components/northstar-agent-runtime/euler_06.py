"""Hierholzer Eulerian trail directed (EULER-006), Real."""
from __future__ import annotations
import ast

VERSION = "euler-06.v1"

def _is_circuit_d(edges, path):
    need = {}
    for u, v in edges:
        need[(u, v)] = need.get((u, v), 0) + 1
    if not edges:
        return path == [] or (len(path) == 1)
    if not path or path[0] != path[-1]:
        return False
    for a, b in zip(path, path[1:]):
        if need.get((a, b), 0) == 0:
            return False
        need[(a, b)] -= 1
    return all(v == 0 for v in need.values())


def _is_trail_d(edges, path):
    need = {}
    for u, v in edges:
        need[(u, v)] = need.get((u, v), 0) + 1
    if not edges:
        return path == []
    if not path:
        return False
    for a, b in zip(path, path[1:]):
        if need.get((a, b), 0) == 0:
            return False
        need[(a, b)] -= 1
    return all(v == 0 for v in need.values())

def eulerian_trail_directed(edges):
    """Hierholzer directed trail. Returns trail or []."""
    adj = {}
    bal = {}
    for i, (u, v) in enumerate(edges):
        adj.setdefault(u, []).append((v, i))
        bal[u] = bal.get(u, 0) + 1
        bal[v] = bal.get(v, 0) - 1
    used = [False] * len(edges)
    starts = [u for u, b in bal.items() if b == 1]
    ends = [u for u, b in bal.items() if b == -1]
    if not ((len(starts) == 1 and len(ends) == 1) or (not starts and not ends)):
        return []
    if not all(b == 0 or (u in starts) or (u in ends) for u, b in bal.items()):
        return []
    start = starts[0] if starts else next((u for u in adj if adj[u]), None)
    if start is None:
        return []
    stack = [start]
    path = []
    while stack:
        u = stack[-1]
        while u in adj and adj[u] and used[adj[u][-1][1]]:
            adj[u].pop()
        if u in adj and adj[u]:
            v, i = adj[u].pop()
            if used[i]:
                continue
            used[i] = True
            stack.append(v)
        else:
            path.append(stack.pop())
    path.reverse()
    return path if all(used) else []

def main() -> None:
    p = [(0, 1), (1, 2), (2, 3)]
    t = eulerian_trail_directed(p)
    assert _is_trail_d(p, t) and t[0] == 0 and t[-1] == 3
    cyc = [(0, 1), (1, 2), (2, 0)]
    assert _is_trail_d(cyc, eulerian_trail_directed(cyc))
    bad = [(0, 1), (0, 2)]
    assert eulerian_trail_directed(bad) == []
    assert eulerian_trail_directed([]) == []
    w = [(0, 1), (1, 2), (2, 1), (1, 3)]
    t2 = eulerian_trail_directed(w)
    assert _is_trail_d(w, t2) and t2[0] == 0 and t2[-1] == 3
    assert stdlib_only()
    print("euler-06.v1 OK")

def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib", "typing", "heapq", "collections", "math", "itertools", "functools", "dataclasses"}
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
