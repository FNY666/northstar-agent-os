"""Two row grid Hamiltonian path snake (HAM-018), Real."""
from __future__ import annotations
import ast

VERSION = "ham-18.v1"

def grid2n_path(cols):
    path = []
    for c in range(cols):
        path.append((0, c))
    for c in range(cols - 1, -1, -1):
        path.append((1, c))
    return path

def grid2n_edges(cols):
    e = []
    for r in range(2):
        for c in range(cols - 1):
            e.append(((r, c), (r, c + 1)))
    for c in range(cols):
        e.append(((0, c), (1, c)))
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
    assert _okg(grid2n_edges(4), grid2n_path(4))
    assert _okg(grid2n_edges(1), grid2n_path(1))
    assert _okg(grid2n_edges(7), grid2n_path(7))
    p = grid2n_path(3)
    assert len(p) == 6 and len(set(p)) == 6
    assert _okg(grid2n_edges(2), grid2n_path(2))
    assert stdlib_only()
    print('ham-18.v1 OK')
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
