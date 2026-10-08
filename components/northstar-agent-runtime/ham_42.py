"""Moon Moser bipartite condition check (HAM-042), Real."""
from __future__ import annotations
import ast

VERSION = "ham-42.v1"

def moon_moser_hamiltonian(m, edges):
    import itertools
    n = 2 * m
    if m < 2:
        return False
    nbr = {v: set() for v in range(n)}
    for u, v in edges:
        nbr[u].add(v)
        nbr[v].add(u)
    X = list(range(m))
    Y = list(range(m, n))
    for r in range(1, m + 1):
        for S in itertools.combinations(X, r):
            if len(set().union(*(nbr[v] for v in S))) < r:
                return False
        for S in itertools.combinations(Y, r):
            if len(set().union(*(nbr[v] for v in S))) < r:
                return False
    return True

def _k33(m):
    return [(x, m + y) for x in range(m) for y in range(m)]

def main() -> None:
    assert moon_moser_hamiltonian(3, _k33(3)) is True
    e = [e for e in _k33(3) if e[0] != 0]
    assert moon_moser_hamiltonian(3, e) is False
    assert moon_moser_hamiltonian(2, _k33(2)) is True
    assert moon_moser_hamiltonian(1, [(0, 1)]) is False
    assert moon_moser_hamiltonian(4, _k33(4)) is True
    assert stdlib_only()
    print('ham-42.v1 OK')
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
