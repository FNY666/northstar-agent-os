"""Complete graph Hamiltonian circuit constructive (HAM-016), Real."""
from __future__ import annotations
import ast

VERSION = "ham-16.v1"

def complete_circuit(n):
    return list(range(n))

def complete_edges(n):
    return [(i, j) for i in range(n) for j in range(i + 1, n)]

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
    assert _okc(5, complete_edges(5), complete_circuit(5))
    assert _okc(3, complete_edges(3), complete_circuit(3))
    assert complete_circuit(0) == []
    assert _okc(7, complete_edges(7), complete_circuit(7))
    assert _okc(4, complete_edges(4), complete_circuit(4))
    assert stdlib_only()
    print('ham-16.v1 OK')
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
