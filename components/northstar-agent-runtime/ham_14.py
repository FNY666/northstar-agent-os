"""Tournament Hamiltonian path constructive (HAM-014), Real."""
from __future__ import annotations
import ast

VERSION = "ham-14.v1"

def _dok(n, edges, path):
    if len(path) != n or len(set(path)) != n:
        return False
    s = set(edges)
    return all((path[i], path[i + 1]) in s for i in range(n - 1))

def tournament_ham_path(n, edges):
    if n == 0:
        return []
    eset = set(edges)
    path = [0]
    for v in range(1, n):
        i = 0
        while i < len(path) and (v, path[i]) not in eset:
            i += 1
        path.insert(i, v)
    return path

def main() -> None:
    e = [(i, j) for i in range(4) for j in range(i + 1, 4)]
    assert _dok(4, e, tournament_ham_path(4, e))
    import random
    rng = random.Random(42)
    n = 8
    e2 = []
    for i in range(n):
        for j in range(i + 1, n):
            if rng.random() < 0.5:
                e2.append((i, j))
            else:
                e2.append((j, i))
    assert _dok(n, e2, tournament_ham_path(n, e2))
    assert tournament_ham_path(1, []) == [0]
    assert tournament_ham_path(0, []) == []
    cyc = [(0, 1), (1, 2), (2, 0)]
    assert _dok(3, cyc, tournament_ham_path(3, cyc))
    assert stdlib_only()
    print('ham-14.v1 OK')
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
