"""Eulerian circuit ignoring isolated vertices (EULER-043), Real."""
from __future__ import annotations
import ast

VERSION = "euler-43.v1"

def _norm(e):
    u, v = e
    return (u, v) if u <= v else (v, u)


def _is_circuit(edges, path):
    need = {}
    for e in edges:
        k = _norm(e)
        need[k] = need.get(k, 0) + 1
    if not edges:
        return path == [] or (len(path) == 1)
    if not path or path[0] != path[-1]:
        return False
    for a, b in zip(path, path[1:]):
        k = _norm((a, b))
        if need.get(k, 0) == 0:
            return False
        need[k] -= 1
    return all(v == 0 for v in need.values())


def _is_trail(edges, path):
    need = {}
    for e in edges:
        k = _norm(e)
        need[k] = need.get(k, 0) + 1
    if not edges:
        return path == []
    if not path:
        return False
    for a, b in zip(path, path[1:]):
        k = _norm((a, b))
        if need.get(k, 0) == 0:
            return False
        need[k] -= 1
    return all(v == 0 for v in need.values())

def eulerian_circuit_ignore_isolated(edges, isolated):
    """Circuit over edges; isolated vertices listed separately are ignored."""
    adj = {}
    for i, (u, v) in enumerate(edges):
        adj.setdefault(u, []).append((v, i))
        adj.setdefault(v, []).append((u, i))
    used = [False] * len(edges)
    start = next((u for u in adj if adj[u]), None)
    if start is None:
        return []
    stack = [start]
    path = []
    while stack:
        u = stack[-1]
        while adj[u] and used[adj[u][-1][1]]:
            adj[u].pop()
        if adj[u]:
            v, i = adj[u].pop()
            if used[i]:
                continue
            used[i] = True
            stack.append(v)
        else:
            path.append(stack.pop())
    path.reverse()
    ok = all(used)
    ok = ok and all(v not in path for v in isolated)
    return path if ok else []

def main() -> None:
    tri = [(0, 1), (1, 2), (2, 0)]
    c = eulerian_circuit_ignore_isolated(tri, [7, 8, 9])
    assert _is_circuit(tri, c)
    assert eulerian_circuit_ignore_isolated(tri, [0]) == []
    assert eulerian_circuit_ignore_isolated([], [1]) == []
    sq = [(0, 1), (1, 2), (2, 3), (3, 0)]
    assert _is_circuit(sq, eulerian_circuit_ignore_isolated(sq, [5]))
    assert stdlib_only()
    print("euler-43.v1 OK")

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
