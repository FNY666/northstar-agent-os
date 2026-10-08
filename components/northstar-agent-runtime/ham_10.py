"""Dirac theorem sufficient condition check (HAM-010), Real."""
from __future__ import annotations
import ast

VERSION = "ham-10.v1"

def dirac_hamiltonian(n, edges):
    if n < 3:
        return False
    deg = [0] * n
    for u, v in edges:
        deg[u] += 1
        deg[v] += 1
    return min(deg) * 2 >= n

def main() -> None:
    k4 = [(i, j) for i in range(4) for j in range(i + 1, 4)]
    assert dirac_hamiltonian(4, k4) is True
    k5 = [(i, j) for i in range(5) for j in range(i + 1, 5)]
    assert dirac_hamiltonian(5, k5) is True
    c5 = [(i, (i + 1) % 5) for i in range(5)]
    assert dirac_hamiltonian(5, c5) is False
    p4 = [(0, 1), (1, 2), (2, 3)]
    assert dirac_hamiltonian(4, p4) is False
    assert dirac_hamiltonian(2, [(0, 1)]) is False
    assert stdlib_only()
    print('ham-10.v1 OK')
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
