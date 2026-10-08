"""Chvatal degree sequence condition check (HAM-012), Real."""
from __future__ import annotations
import ast

VERSION = "ham-12.v1"

def chvatal_hamiltonian(n, edges):
    if n < 3:
        return False
    deg = [0] * n
    for u, v in edges:
        deg[u] += 1
        deg[v] += 1
    d = sorted(deg)
    for k in range(1, n // 2 + 1):
        if k >= (n + 1) // 2:
            break
        if not (d[k - 1] > k or d[n - k - 1] >= n - k):
            return False
    return True

def main() -> None:
    k4 = [(i, j) for i in range(4) for j in range(i + 1, 4)]
    assert chvatal_hamiltonian(4, k4) is True
    p4 = [(0, 1), (1, 2), (2, 3)]
    assert chvatal_hamiltonian(4, p4) is False
    c5 = [(i, (i + 1) % 5) for i in range(5)]
    assert chvatal_hamiltonian(5, c5) is False
    k5 = [(i, j) for i in range(5) for j in range(i + 1, 5)]
    assert chvatal_hamiltonian(5, k5) is True
    assert chvatal_hamiltonian(2, [(0, 1)]) is False
    assert stdlib_only()
    print('ham-12.v1 OK')
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
