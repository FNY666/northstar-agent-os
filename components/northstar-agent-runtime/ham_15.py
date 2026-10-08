"""Complete graph Hamiltonian path constructive (HAM-015), Real."""
from __future__ import annotations
import ast

VERSION = "ham-15.v1"

def complete_path(n):
    return list(range(n))

def complete_edges(n):
    return [(i, j) for i in range(n) for j in range(i + 1, n)]

def _ok(n, edges, path):
    if len(path) != n or len(set(path)) != n:
        return False
    s = set()
    for u, v in edges:
        s.add((u, v))
        s.add((v, u))
    return all((path[i], path[i + 1]) in s for i in range(n - 1))

def main() -> None:
    assert _ok(5, complete_edges(5), complete_path(5))
    assert _ok(1, [], complete_path(1))
    assert complete_path(0) == []
    assert _ok(8, complete_edges(8), complete_path(8))
    assert _ok(2, complete_edges(2), complete_path(2))
    assert stdlib_only()
    print('ham-15.v1 OK')
def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib", "typing", "heapq", "collections", "math", "itertools", "functools", "dataclasses", "random"}
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
