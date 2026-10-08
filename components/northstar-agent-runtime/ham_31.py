"""Hamiltonian circuit certificate verifier (HAM-031), Real."""
from __future__ import annotations
import ast

VERSION = "ham-31.v1"

def verify_ham_circuit(n, edges, path):
    if len(path) != n or len(set(path)) != n:
        return False
    if n == 0:
        return True
    if any(v < 0 or v >= n for v in path):
        return False
    s = set()
    for u, v in edges:
        s.add((u, v))
        s.add((v, u))
    c = path + [path[0]]
    return all((c[i], c[i + 1]) in s for i in range(n))

def main() -> None:
    sq = [(0, 1), (1, 2), (2, 3), (3, 0)]
    assert verify_ham_circuit(4, sq, [0, 1, 2, 3]) is True
    assert verify_ham_circuit(4, sq, [0, 1, 3, 2]) is False
    assert verify_ham_circuit(4, sq, [0, 1, 2]) is False
    assert verify_ham_circuit(4, sq, [0, 1, 2, 2]) is False
    assert verify_ham_circuit(0, [], []) is True
    assert stdlib_only()
    print('ham-31.v1 OK')
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
