"""Validate directed Eulerian circuit candidate (EULER-023), Real."""
from __future__ import annotations
import ast

VERSION = "euler-23.v1"

def _is_circuit_d(edges, path):
    need = {}
    for u, v in edges:
        need[(u, v)] = need.get((u, v), 0) + 1
    if not edges:
        return path == [] or (len(path) == 1)
    if not path or path[0] != path[-1]:
        return False
    for a, b in zip(path, path[1:]):
        if need.get((a, b), 0) == 0:
            return False
        need[(a, b)] -= 1
    return all(v == 0 for v in need.values())


def _is_trail_d(edges, path):
    need = {}
    for u, v in edges:
        need[(u, v)] = need.get((u, v), 0) + 1
    if not edges:
        return path == []
    if not path:
        return False
    for a, b in zip(path, path[1:]):
        if need.get((a, b), 0) == 0:
            return False
        need[(a, b)] -= 1
    return all(v == 0 for v in need.values())

def main() -> None:
    cyc = [(0, 1), (1, 2), (2, 0)]
    assert _is_circuit_d(cyc, [0, 1, 2, 0])
    assert not _is_circuit_d(cyc, [0, 2, 1, 0])
    assert not _is_circuit_d(cyc, [0, 1, 2])
    assert _is_trail_d([(0, 1), (1, 2)], [0, 1, 2])
    assert not _is_trail_d([(0, 1), (1, 2)], [2, 1, 0])
    assert _is_circuit_d([], [])
    assert stdlib_only()
    print("euler-23.v1 OK")

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
