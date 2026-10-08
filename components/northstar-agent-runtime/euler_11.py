"""Fleury Eulerian circuit undirected (EULER-011), Real."""
from __future__ import annotations
import ast

VERSION = "euler-11.v1"

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

def _reach(adj, src, used):
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


def fleury_circuit(edges):
    """Fleury's algorithm: avoid bridges. Returns circuit or []."""
    adj = {}
    for i, (u, v) in enumerate(edges):
        adj.setdefault(u, []).append((v, i))
        adj.setdefault(v, []).append((u, i))
    if any(len(adj[u]) % 2 for u in adj):
        return []
    start = next((u for u in adj if adj[u]), None)
    if start is None:
        return []
    used = set()
    path = [start]
    u = start
    for _ in range(len(edges)):
        cands = [(v, i) for v, i in adj[u] if i not in used]
        if not cands:
            return []
        pick = cands[0]
        if len(cands) > 1:
            for v, i in cands:
                if v in _reach(adj, u, used | {i}):
                    pick = (v, i)
                    break
        v, i = pick
        used.add(i)
        path.append(v)
        u = v
    return path

def main() -> None:
    tri = [(0, 1), (1, 2), (2, 0)]
    assert _is_circuit(tri, fleury_circuit(tri))
    sq = [(0, 1), (1, 2), (2, 3), (3, 0)]
    assert _is_circuit(sq, fleury_circuit(sq))
    assert fleury_circuit([(0, 1), (1, 2)]) == []
    assert fleury_circuit([]) == []
    dbl = [(0, 1), (0, 1), (1, 2), (1, 2), (2, 0), (2, 0)]
    assert _is_circuit(dbl, fleury_circuit(dbl))
    assert stdlib_only()
    print("euler-11.v1 OK")

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
