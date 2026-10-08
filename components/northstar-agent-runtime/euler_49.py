"""Count valid trail start vertices (EULER-049), Real."""
from __future__ import annotations
import ast

VERSION = "euler-49.v1"

def valid_trail_starts(edges):
    """Vertices from which an Eulerian trail can start."""
    if not edges:
        return []
    deg = {}
    for u, v in edges:
        deg[u] = deg.get(u, 0) + 1
        deg[v] = deg.get(v, 0) + 1
    odds = [u for u, d in deg.items() if d % 2 == 1]
    if len(odds) == 2:
        return sorted(odds)
    if len(odds) == 0:
        return sorted(deg)
    return []

def main() -> None:
    assert valid_trail_starts([(0, 1), (1, 2), (2, 3)]) == [0, 3]
    assert valid_trail_starts([(0, 1), (1, 2), (2, 0)]) == [0, 1, 2]
    assert valid_trail_starts([(0, 1), (0, 2), (0, 3)]) == []
    assert valid_trail_starts([]) == []
    assert valid_trail_starts([(5, 6)]) == [5, 6]
    assert stdlib_only()
    print("euler-49.v1 OK")

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
