"""Three row grid Hamiltonian path even columns (HAM-033), Real."""
from __future__ import annotations
import ast

VERSION = "ham-33.v1"

def grid3n_path(cols):
    if cols % 2 != 0:
        return []
    path = []
    for c in range(cols):
        path.append((0, c))
    for c in range(cols - 1, -1, -1):
        path.append((1, c))
    for c in range(cols):
        path.append((2, c))
    return path

def grid3n_edges(cols):
    e = []
    for r in range(3):
        for c in range(cols - 1):
            e.append(((r, c), (r, c + 1)))
    for r in range(2):
        for c in range(cols):
            e.append(((r, c), (r + 1, c)))
    return e

def _okg(edges, path):
    if len(set(path)) != len(path):
        return False
    verts = set()
    for u, v in edges:
        verts.add(u)
        verts.add(v)
    if set(path) != verts:
        return False
    s = set()
    for u, v in edges:
        s.add((u, v))
        s.add((v, u))
    return all((path[i], path[i + 1]) in s for i in range(len(path) - 1))

def main() -> None:
    assert _okg(grid3n_edges(4), grid3n_path(4))
    assert _okg(grid3n_edges(2), grid3n_path(2))
    assert grid3n_path(3) == []
    assert len(grid3n_path(6)) == 18
    assert _okg(grid3n_edges(6), grid3n_path(6))
    assert stdlib_only()
    print('ham-33.v1 OK')
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
