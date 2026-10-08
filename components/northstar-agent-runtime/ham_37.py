"""Circulant graph Hamiltonian cycle (HAM-037), Real."""
from __future__ import annotations
import ast

VERSION = "ham-37.v1"

def circulant_cycle(n, jumps):
    if 1 not in jumps and (n - 1) not in jumps:
        return []
    return list(range(n))

def circulant_edges(n, jumps):
    e = set()
    for i in range(n):
        for j in jumps:
            u, v = i, (i + j) % n
            if u != v:
                e.add((min(u, v), max(u, v)))
    return sorted(e)

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
    assert _okc(7, circulant_edges(7, {1, 2}), circulant_cycle(7, {1, 2}))
    assert circulant_cycle(7, {2, 3}) == []
    assert _okc(5, circulant_edges(5, {1}), circulant_cycle(5, {1}))
    assert _okc(8, circulant_edges(8, {1, 3}), circulant_cycle(8, {1, 3}))
    assert circulant_cycle(4, {2}) == []
    assert stdlib_only()
    print('ham-37.v1 OK')
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
