"""Rotate Eulerian circuit to start vertex (EULER-039), Real."""
from __future__ import annotations
import ast

VERSION = "euler-39.v1"

def _norm(e):
    u, v = e
    return (u, v) if u <= v else (v, u)


def _is_circuit(edges, path):
    need = {}
    for e in edges:
        k = _norm(e)
        need[k] = need.get(k, 0) + 1
    if not edges:
        return path == [] or (len(path) == 1)
    if not path or path[0] != path[-1]:
        return False
    for a, b in zip(path, path[1:]):
        k = _norm((a, b))
        if need.get(k, 0) == 0:
            return False
        need[k] -= 1
    return all(v == 0 for v in need.values())


def _is_trail(edges, path):
    need = {}
    for e in edges:
        k = _norm(e)
        need[k] = need.get(k, 0) + 1
    if not edges:
        return path == []
    if not path:
        return False
    for a, b in zip(path, path[1:]):
        k = _norm((a, b))
        if need.get(k, 0) == 0:
            return False
        need[k] -= 1
    return all(v == 0 for v in need.values())

def rotate_circuit(circuit, start):
    """Rotate a circuit so it begins (and ends) at start."""
    if not circuit or start not in circuit:
        return []
    i = circuit.index(start)
    return circuit[i:-1] + circuit[:i] + [start]

def main() -> None:
    c = [0, 1, 2, 3, 0]
    assert rotate_circuit(c, 2) == [2, 3, 0, 1, 2]
    assert rotate_circuit(c, 0) == c
    assert rotate_circuit(c, 9) == []
    assert rotate_circuit([], 0) == []
    tri = [(0, 1), (1, 2), (2, 0)]
    assert _is_circuit(tri, rotate_circuit([0, 1, 2, 0], 1))
    assert stdlib_only()
    print("euler-39.v1 OK")

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
