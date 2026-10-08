"""Odd degree vertices list (EULER-019), Real."""
from __future__ import annotations
import ast

VERSION = "euler-19.v1"

def odd_vertices(edges):
    """Sorted list of vertices with odd degree."""
    deg = {}
    for u, v in edges:
        deg[u] = deg.get(u, 0) + 1
        deg[v] = deg.get(v, 0) + 1
    return sorted(u for u, d in deg.items() if d % 2 == 1)

def main() -> None:
    assert odd_vertices([(0, 1), (1, 2), (2, 3)]) == [0, 3]
    assert odd_vertices([(0, 1), (1, 2), (2, 0)]) == []
    assert odd_vertices([(0, 1), (0, 2), (0, 3)]) == [0, 1, 2, 3]
    assert odd_vertices([]) == []
    assert odd_vertices([(0, 0), (0, 1)]) == [0, 1]
    assert stdlib_only()
    print("euler-19.v1 OK")

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
