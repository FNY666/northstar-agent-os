"""Eulerian trail endpoints directed (EULER-018), Real."""
from __future__ import annotations
import ast

VERSION = "euler-18.v1"

def trail_endpoints_directed(edges):
    """Return (start, end) for a directed Eulerian trail, or None."""
    if not edges:
        return None
    bal = {}
    for u, v in edges:
        bal[u] = bal.get(u, 0) + 1
        bal[v] = bal.get(v, 0) - 1
    starts = [u for u, b in bal.items() if b == 1]
    ends = [u for u, b in bal.items() if b == -1]
    if not all(b in (-1, 0, 1) for b in bal.values()):
        return None
    if len(starts) == 1 and len(ends) == 1:
        return (starts[0], ends[0])
    if not starts and not ends:
        s = next(iter(bal))
        return (s, s)
    return None

def main() -> None:
    assert trail_endpoints_directed([(0, 1), (1, 2), (2, 3)]) == (0, 3)
    s, e = trail_endpoints_directed([(0, 1), (1, 2), (2, 0)])
    assert s == e
    assert trail_endpoints_directed([(0, 1), (0, 2)]) is None
    assert trail_endpoints_directed([]) is None
    assert trail_endpoints_directed([(7, 8)]) == (7, 8)
    assert stdlib_only()
    print("euler-18.v1 OK")

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
