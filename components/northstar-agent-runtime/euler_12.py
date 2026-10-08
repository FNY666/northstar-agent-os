"""Fleury Eulerian circuit directed (EULER-012), Real."""
from __future__ import annotations
import ast

VERSION = "euler-12.v1"

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

def _reach_d(adj, src, used):
    seen = {src}
    stack = [src]
    while stack:
        u = stack.pop()
        for v, i in adj.get(u, ()):
            if i in used or v in seen:
                continue
            seen.add(v)
            stack.append(v)
    return seen


def fleury_circuit_directed(edges):
    """Fleury's algorithm on directed graph. Returns circuit or []."""
    adj = {}
    bal = {}
    for i, (u, v) in enumerate(edges):
        adj.setdefault(u, []).append((v, i))
        bal[u] = bal.get(u, 0) + 1
        bal[v] = bal.get(v, 0) - 1
    if any(bal.values()):
        return []
    start = next((u for u in adj if adj[u]), None)
    if start is None:
        return []
    used = set()
    path = [start]
    u = start
    for _ in range(len(edges)):
        cands = [(v, i) for v, i in adj.get(u, ()) if i not in used]
        if not cands:
            return []
        pick = cands[0]
        if len(cands) > 1:
            for v, i in cands:
                if v in _reach_d(adj, u, used | {i}):
                    pick = (v, i)
                    break
        v, i = pick
        used.add(i)
        path.append(v)
        u = v
    return path

def main() -> None:
    cyc = [(0, 1), (1, 2), (2, 0)]
    assert _is_circuit_d(cyc, fleury_circuit_directed(cyc))
    fig8 = [(0, 1), (1, 0), (0, 2), (2, 0)]
    assert _is_circuit_d(fig8, fleury_circuit_directed(fig8))
    assert fleury_circuit_directed([(0, 1)]) == []
    assert fleury_circuit_directed([]) == []
    bad = [(0, 1), (1, 2), (2, 1)]
    assert fleury_circuit_directed(bad) == []
    assert stdlib_only()
    print("euler-12.v1 OK")

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
