"""Circuit to ordered edge list (EULER-050), Real."""
from __future__ import annotations
import ast

VERSION = "euler-50.v1"

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

def circuit_to_edges(circuit):
    """Convert vertex circuit to ordered edge list."""
    return [(a, b) for a, b in zip(circuit, circuit[1:])]


def edges_to_circuit_check(edges, circuit):
    """True iff circuit uses each edge exactly once (undirected)."""
    return _is_circuit(edges, circuit)

def main() -> None:
    assert circuit_to_edges([0, 1, 2, 0]) == [(0, 1), (1, 2), (2, 0)]
    assert circuit_to_edges([]) == []
    assert circuit_to_edges([3]) == []
    tri = [(0, 1), (1, 2), (2, 0)]
    assert edges_to_circuit_check(tri, [0, 1, 2, 0])
    assert not edges_to_circuit_check(tri, [0, 1, 0, 2, 0])
    assert edges_to_circuit_check([], [])
    assert stdlib_only()
    print("euler-50.v1 OK")

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
