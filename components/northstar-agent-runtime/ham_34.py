"""Prism graph Hamiltonian cycle constructive (HAM-034), Real."""
from __future__ import annotations
import ast

VERSION = "ham-34.v1"

def prism_cycle(n):
    outer = list(range(n))
    inner = list(range(2 * n - 1, n - 1, -1))
    return outer + inner

def prism_edges(n):
    e = []
    for i in range(n):
        e.append((i, (i + 1) % n))
        e.append((n + i, n + (i + 1) % n))
        e.append((i, n + i))
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
    assert _okc(8, prism_edges(4), prism_cycle(4))
    assert _okc(10, prism_edges(5), prism_cycle(5))
    assert _okc(6, prism_edges(3), prism_cycle(3))
    assert len(prism_cycle(4)) == 8
    assert len(set(prism_cycle(5))) == 10
    assert stdlib_only()
    print('ham-34.v1 OK')
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
