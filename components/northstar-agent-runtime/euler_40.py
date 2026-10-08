"""Close Eulerian trail into circuit (EULER-040), Real."""
from __future__ import annotations
import ast

VERSION = "euler-40.v1"

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

def close_trail(edges, trail):
    """If trail is Eulerian and endpoints differ, add closing edge -> circuit."""
    if not trail:
        return []
    if not _is_trail(edges, trail):
        return []
    if trail[0] == trail[-1]:
        return trail
    new_edges = edges + [(trail[-1], trail[0])]
    return trail + [trail[0]]

def main() -> None:
    line = [(0, 1), (1, 2), (2, 3)]
    t = [0, 1, 2, 3]
    c = close_trail(line, t)
    assert _is_circuit(line + [(3, 0)], c)
    tri = [(0, 1), (1, 2), (2, 0)]
    assert close_trail(tri, [0, 1, 2, 0]) == [0, 1, 2, 0]
    assert close_trail(line, [0, 1, 2]) == []
    assert close_trail([], []) == []
    assert stdlib_only()
    print("euler-40.v1 OK")

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
