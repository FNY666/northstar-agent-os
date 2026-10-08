"""Hierholzer Eulerian circuit directed recursive (EULER-004), Real."""
from __future__ import annotations
import ast

VERSION = "euler-04.v1"

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

def eulerian_circuit_directed_rec(edges):
    """Recursive Hierholzer on directed edge list. Returns circuit or []."""
    adj = {}
    for i, (u, v) in enumerate(edges):
        adj.setdefault(u, []).append([v, i])
    used = [False] * len(edges)
    start = next((u for u in adj if adj[u]), None)
    if start is None:
        return []
    path = []

    def dfs(u):
        while u in adj and adj[u]:
            v, i = adj[u].pop()
            if used[i]:
                continue
            used[i] = True
            dfs(v)
        path.append(u)

    dfs(start)
    path.reverse()
    return path if (all(used) and len(path) > 1 and path[0] == path[-1]) else []

def main() -> None:
    cyc = [(0, 1), (1, 2), (2, 0)]
    assert _is_circuit_d(cyc, eulerian_circuit_directed_rec(cyc))
    fig8 = [(0, 1), (1, 0), (0, 2), (2, 0)]
    assert _is_circuit_d(fig8, eulerian_circuit_directed_rec(fig8))
    assert eulerian_circuit_directed_rec([(0, 1)]) == []
    assert eulerian_circuit_directed_rec([]) == []
    par = [(0, 1), (0, 1), (1, 0), (1, 0)]
    assert _is_circuit_d(par, eulerian_circuit_directed_rec(par))
    assert stdlib_only()
    print("euler-04.v1 OK")

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
