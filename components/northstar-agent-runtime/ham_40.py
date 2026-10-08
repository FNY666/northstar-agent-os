"""Wheel graph Hamiltonian cycle constructive (HAM-040), Real."""
from __future__ import annotations
import ast

VERSION = "ham-40.v1"

def wheel_cycle(n):
    if n < 4:
        return []
    return [0] + list(range(1, n))

def wheel_edges(n):
    e = [(0, i) for i in range(1, n)]
    e += [(i, i + 1) for i in range(1, n - 1)] + [(n - 1, 1)]
    return e

def _okc(n, edges, path):
    if len(path) != n or len(set(path)) != n:
        return False
    s = set()
    for u, v in edges:
        s.add((u, v))
        s.add((v, u))
    c = path + [path[0]]
    return all((c[i], c[i + 1]) in s for i in range(n))

def main() -> None:
    assert _okc(5, wheel_edges(5), wheel_cycle(5))
    assert _okc(6, wheel_edges(6), wheel_cycle(6))
    assert _okc(8, wheel_edges(8), wheel_cycle(8))
    assert wheel_cycle(3) == []
    assert len(wheel_cycle(7)) == 7
    assert stdlib_only()
    print('ham-40.v1 OK')
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
