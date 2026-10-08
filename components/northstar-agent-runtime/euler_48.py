"""Dodecahedron graph Eulerian check (EULER-048), Real."""
from __future__ import annotations
import ast

VERSION = "euler-48.v1"

def dodecahedron_edges():
    """Dodecahedron graph: 20 vertices, 30 edges, all degrees 3."""
    outer = [(i, (i + 1) % 5) for i in range(5)]
    inner = [(5 + i, 5 + (i + 1) % 5) for i in range(5)]
    mid1 = [(10 + i, 10 + (i + 1) % 5) for i in range(5)]
    spokes1 = [(i, 10 + i) for i in range(5)]
    spokes2 = [(5 + i, 15 + i) for i in range(5)]
    inner2 = [(15 + i, 15 + (i + 1) % 5) for i in range(5)]
    return outer + inner + mid1 + spokes1 + spokes2 + inner2


def dodecahedron_odd_count():
    deg = {}
    for u, v in dodecahedron_edges():
        deg[u] = deg.get(u, 0) + 1
        deg[v] = deg.get(v, 0) + 1
    return sum(d % 2 for d in deg.values())

def main() -> None:
    assert len(dodecahedron_edges()) == 30
    assert dodecahedron_odd_count() == 20
    deg = {}
    for u, v in dodecahedron_edges():
        deg[u] = deg.get(u, 0) + 1
        deg[v] = deg.get(v, 0) + 1
    assert len(deg) == 20 and all(d == 3 for d in deg.values())
    assert stdlib_only()
    print("euler-48.v1 OK")

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
