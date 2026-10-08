"""Petersen graph Eulerian check (EULER-037), Real."""
from __future__ import annotations
import ast

VERSION = "euler-37.v1"

def petersen_edges():
    """Petersen graph: outer 5-cycle, inner 5-star, 5 spokes."""
    edges = [(i, (i + 1) % 5) for i in range(5)]
    edges += [(5 + i, 5 + (i + 2) % 5) for i in range(5)]
    edges += [(i, 5 + i) for i in range(5)]
    return edges


def petersen_odd_count():
    deg = {}
    for u, v in petersen_edges():
        deg[u] = deg.get(u, 0) + 1
        deg[v] = deg.get(v, 0) + 1
    return sum(d % 2 for d in deg.values())

def main() -> None:
    assert len(petersen_edges()) == 15
    assert petersen_odd_count() == 10
    deg = {}
    for u, v in petersen_edges():
        deg[u] = deg.get(u, 0) + 1
        deg[v] = deg.get(v, 0) + 1
    assert all(d == 3 for d in deg.values())
    assert len(deg) == 10
    assert stdlib_only()
    print("euler-37.v1 OK")

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
