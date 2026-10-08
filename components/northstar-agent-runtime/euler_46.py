"""Eulerian circuit of 4-cube Q4 (EULER-046), Real."""
from __future__ import annotations
import ast

VERSION = "euler-46.v1"

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

def q4_edges():
    """Edges of 4-dimensional hypercube (16 vertices, 32 edges)."""
    edges = []
    for u in range(16):
        for b in range(4):
            v = u ^ (1 << b)
            if u < v:
                edges.append((u, v))
    return edges


def eulerian_circuit_q4():
    edges = q4_edges()
    adj = {}
    for i, (u, v) in enumerate(edges):
        adj.setdefault(u, []).append((v, i))
        adj.setdefault(v, []).append((u, i))
    used = [False] * len(edges)
    stack = [0]
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
    e = q4_edges()
    assert len(e) == 32
    c = eulerian_circuit_q4()
    assert _is_circuit(e, c)
    assert len(c) == 33 and c[0] == c[-1]
    assert len(set(c)) == 16
    assert stdlib_only()
    print("euler-46.v1 OK")

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
