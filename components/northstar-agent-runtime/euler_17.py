"""Eulerian trail endpoints undirected (EULER-017), Real."""
from __future__ import annotations
import ast

VERSION = "euler-17.v1"

def trail_endpoints(edges):
    """Return (start, end) for an Eulerian trail, or None if none exists."""
    if not edges:
        return None
    deg = {}
    for u, v in edges:
        deg[u] = deg.get(u, 0) + 1
        deg[v] = deg.get(v, 0) + 1
    odds = sorted(u for u, d in deg.items() if d % 2 == 1)
    if len(odds) == 0:
        s = next(iter(deg))
        return (s, s)
    if len(odds) == 2:
        return (odds[0], odds[1])
    return None

def main() -> None:
    assert trail_endpoints([(0, 1), (1, 2), (2, 3)]) == (0, 3)
    s, e = trail_endpoints([(0, 1), (1, 2), (2, 0)])
    assert s == e
    assert trail_endpoints([(0, 1), (0, 2), (0, 3)]) is None
    assert trail_endpoints([]) is None
    assert trail_endpoints([(4, 5)]) == (4, 5)
    assert stdlib_only()
    print("euler-17.v1 OK")

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
