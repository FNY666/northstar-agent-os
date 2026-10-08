"""Eulerian existence check directed (EULER-016), Real."""
from __future__ import annotations
import ast

VERSION = "euler-16.v1"

def has_eulerian_directed(edges):
    """True iff directed edge list has Eulerian circuit or trail."""
    if not edges:
        return True
    bal = {}
    adj = {}
    for u, v in edges:
        bal[u] = bal.get(u, 0) + 1
        bal[v] = bal.get(v, 0) - 1
        adj.setdefault(u, []).append(v)
        adj.setdefault(v, []).append(u)
    vals = sorted(bal.values())
    if not (all(x == 0 for x in vals) or vals.count(1) == 1 and vals.count(-1) == 1 and all(x in (0, 1, -1) for x in vals)):
        return False
    start = next(iter(adj))
    seen = {start}
    stack = [start]
    while stack:
        u = stack.pop()
        for v in adj[u]:
            if v not in seen:
                seen.add(v)
                stack.append(v)
    return all(u in seen for u in bal)

def main() -> None:
    assert has_eulerian_directed([(0, 1), (1, 2), (2, 0)])
    assert has_eulerian_directed([(0, 1), (1, 2), (2, 3)])
    assert not has_eulerian_directed([(0, 1), (0, 2)])
    assert not has_eulerian_directed([(0, 1), (2, 3)])
    assert has_eulerian_directed([])
    assert has_eulerian_directed([(0, 1), (1, 0), (1, 2), (2, 1)])
    assert stdlib_only()
    print("euler-16.v1 OK")

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
