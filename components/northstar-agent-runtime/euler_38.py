"""Odd vertex pairing count (EULER-038), Real."""
from __future__ import annotations
import ast

VERSION = "euler-38.v1"

def odd_pairing_count(edges):
    """Number of pairs needed to make all degrees even (odd_count / 2)."""
    deg = {}
    for u, v in edges:
        deg[u] = deg.get(u, 0) + 1
        deg[v] = deg.get(v, 0) + 1
    return sum(d % 2 for d in deg.values()) // 2

def main() -> None:
    assert odd_pairing_count([(0, 1), (1, 2), (2, 3)]) == 1
    assert odd_pairing_count([(0, 1), (1, 2), (2, 0)]) == 0
    assert odd_pairing_count([(0, 1), (0, 2), (0, 3)]) == 2
    assert odd_pairing_count([]) == 0
    assert odd_pairing_count([(0, 1), (2, 3)]) == 2
    assert stdlib_only()
    print("euler-38.v1 OK")

def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib", "typing", "heapq", "collections", "math", "itertools", "functools", "dataclasses"}
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
