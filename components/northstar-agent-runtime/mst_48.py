"""MST with forced edge (contract first) (MST-048), Real."""
from __future__ import annotations
import ast

VERSION = "mst-48.v1"

def mst_forced(n, edges, forced):
    fu, fv, fw = forced
    parent = list(range(n))
    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x
    total = 0
    mst = []
    if find(fu) != find(fv):
        parent[find(fv)] = find(fu)
        total += fw
        mst.append(forced)
    for u, v, w in sorted(edges, key=lambda e: e[2]):
        if u == v:
            continue
        if (u, v, w) == forced or (v, u, w) == forced:
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
    r = mst_forced(3, [(0, 1, 1), (1, 2, 2), (0, 2, 3)], (0, 2, 3))
    assert r[0] == 4  # forced (0,2,3) + (0,1,1)
    assert (0, 2, 3) in r[1]
    r = mst_forced(3, [(0, 1, 1), (1, 2, 2), (0, 2, 3)], (0, 1, 1))
    assert r[0] == 3
    assert mst_forced(3, [(0, 1, 1)], (0, 1, 1)) is None
    assert stdlib_only()
    print("mst-48 OK")


if __name__ == "__main__":
    main()
