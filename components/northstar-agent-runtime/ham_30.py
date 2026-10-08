"""Hamiltonian path certificate verifier (HAM-030), Real."""
from __future__ import annotations
import ast

VERSION = "ham-30.v1"

def verify_ham_path(n, edges, path):
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
    return all((path[i], path[i + 1]) in s for i in range(n - 1))

def main() -> None:
    e = [(0, 1), (1, 2), (2, 3)]
    assert verify_ham_path(4, e, [0, 1, 2, 3]) is True
    assert verify_ham_path(4, e, [0, 2, 1, 3]) is False
    assert verify_ham_path(4, e, [0, 1, 2]) is False
    assert verify_ham_path(4, e, [0, 1, 1, 2]) is False
    assert verify_ham_path(0, [], []) is True
    assert stdlib_only()
    print('ham-30.v1 OK')
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
