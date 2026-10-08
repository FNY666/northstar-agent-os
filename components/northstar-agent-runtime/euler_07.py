"""Hierholzer lexicographically smallest circuit undirected (EULER-007), Real."""
from __future__ import annotations
import ast

VERSION = "euler-07.v1"

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

def eulerian_circuit_lex_smallest(edges):
    """Hierholzer consuming smallest neighbor first. Returns circuit or []."""
    adj = {}
    for i, (u, v) in enumerate(edges):
        adj.setdefault(u, []).append((v, i))
        adj.setdefault(v, []).append((u, i))
    for u in adj:
        adj[u].sort(key=lambda e: e[0], reverse=True)
    used = [False] * len(edges)
    start = min((u for u in adj if adj[u]), default=None)
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
    return path if (all(used) and len(path) > 1 and path[0] == path[-1]) else []

def main() -> None:
    tri = [(0, 1), (1, 2), (2, 0)]
    c = eulerian_circuit_lex_smallest(tri)
    assert _is_circuit(tri, c) and c[0] == 0
    assert c == [0, 1, 2, 0]
    sq = [(0, 1), (1, 2), (2, 3), (3, 0)]
    assert eulerian_circuit_lex_smallest(sq) == [0, 1, 2, 3, 0]
    assert eulerian_circuit_lex_smallest([(0, 1)]) == []
    assert eulerian_circuit_lex_smallest([]) == []
    assert stdlib_only()
    print("euler-07.v1 OK")

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
