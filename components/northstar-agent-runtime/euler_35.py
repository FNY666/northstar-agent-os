"""Wheel graph Eulerian check (EULER-035), Real."""
from __future__ import annotations
import ast

VERSION = "euler-35.v1"

def wheel_edges(n):
    """Wheel W_n: hub 0 connected to rim 1..n, rim is a cycle."""
    edges = [(0, i) for i in range(1, n + 1)]
    edges += [(i, i + 1) for i in range(1, n)]
    edges.append((n, 1))
    return edges


def is_eulerian_wheel(n):
    """Wheel graphs are never Eulerian (rim vertices have odd degree 3)."""
    deg = {}
    for u, v in wheel_edges(n):
        deg[u] = deg.get(u, 0) + 1
        deg[v] = deg.get(v, 0) + 1
    return all(d % 2 == 0 for d in deg.values())

def main() -> None:
    assert not is_eulerian_wheel(3)
    assert not is_eulerian_wheel(4)
    assert not is_eulerian_wheel(5)
    assert not is_eulerian_wheel(6)
    e = wheel_edges(4)
    assert len(e) == 8
    assert stdlib_only()
    print("euler-35.v1 OK")

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
