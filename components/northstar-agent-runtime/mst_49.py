"""MST with forbidden edge (exclude and rebuild) (MST-049), Real."""
from __future__ import annotations
import ast

VERSION = "mst-49.v1"

def mst_forbidden(n, edges, forbidden):
    parent = list(range(n))
    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x
    total = 0
    mst = []
    for u, v, w in sorted(edges, key=lambda e: e[2]):
        if u == v:
            continue
        if (u, v, w) == forbidden or (v, u, w) == forbidden:
            continue
        ra, rb = find(u), find(v)
        if ra != rb:
            parent[rb] = ra
            total += w
            mst.append((u, v, w))
            if len(mst) == n - 1:
                break
    if len(mst) != n - 1:
        return None
    return total, mst

def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib", "typing", "heapq", "collections", "math", "itertools", "functools"}
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                if a.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(n, ast.ImportFrom):
            if n.module and n.module.split(".")[0] not in allowed:
                return False
    return True

def main() -> None:
    r = mst_forbidden(3, [(0, 1, 1), (1, 2, 2), (0, 2, 3)], (0, 1, 1))
    assert r[0] == 5  # (1,2,2) + (0,2,3)
    assert (0, 1, 1) not in r[1]
    r = mst_forbidden(3, [(0, 1, 1), (1, 2, 2), (0, 2, 3)], (1, 2, 2))
    assert r[0] == 4
    assert mst_forbidden(2, [(0, 1, 4)], (0, 1, 4)) is None
    assert stdlib_only()
    print("mst-49 OK")


if __name__ == "__main__":
    main()
