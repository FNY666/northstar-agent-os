"""Cycle graph Hamiltonian path constructive (HAM-017), Real."""
from __future__ import annotations
import ast

VERSION = "ham-17.v1"

def cycle_path(n):
    return list(range(n))

def cycle_edges(n):
    return [(i, (i + 1) % n) for i in range(n)]

def _ok(n, edges, path):
    if len(path) != n or len(set(path)) != n:
        return False
    s = set()
    for u, v in edges:
        s.add((u, v))
        s.add((v, u))
    return all((path[i], path[i + 1]) in s for i in range(n - 1))

def main() -> None:
    assert _ok(6, cycle_edges(6), cycle_path(6))
    assert _ok(3, cycle_edges(3), cycle_path(3))
    assert _ok(10, cycle_edges(10), cycle_path(10))
    assert _ok(1, [], cycle_path(1))
    assert cycle_path(0) == []
    assert stdlib_only()
    print('ham-17.v1 OK')
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
