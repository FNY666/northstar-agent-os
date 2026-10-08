"""Weak connectivity ignoring isolated vertices (EULER-020), Real."""
from __future__ import annotations
import ast

VERSION = "euler-20.v1"

def is_weakly_connected(edges):
    """True iff all vertices incident to an edge are in one component."""
    if not edges:
        return True
    adj = {}
    for u, v in edges:
        adj.setdefault(u, []).append(v)
        adj.setdefault(v, []).append(u)
    start = next(iter(adj))
    seen = {start}
    stack = [start]
    while stack:
        u = stack.pop()
        for w in adj[u]:
            if w not in seen:
                seen.add(w)
                stack.append(w)
    return len(seen) == len(adj)

def main() -> None:
    assert is_weakly_connected([(0, 1), (1, 2)])
    assert not is_weakly_connected([(0, 1), (2, 3)])
    assert is_weakly_connected([])
    assert is_weakly_connected([(0, 0)])
    assert is_weakly_connected([(0, 1), (1, 0), (1, 2), (2, 1)])
    assert stdlib_only()
    print("euler-20.v1 OK")

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
