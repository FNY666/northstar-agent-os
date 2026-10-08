"""Minimum bottleneck spanning tree value (MST-033), Real."""
from __future__ import annotations
import ast

VERSION = "mst-33.v1"

def bottleneck(n, edges):
    # The minimum possible maximum edge over all spanning trees equals
    # the maximum edge weight in any MST.
    parent = list(range(n))
    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x
    mx = 0
    cnt = 0
    for u, v, w in sorted(edges, key=lambda e: e[2]):
        if u == v:
            continue
        ru, rv = find(u), find(v)
        if ru != rv:
            parent[rv] = ru
            mx = max(mx, w)
            cnt += 1
            if cnt == n - 1:
                break
    return mx if cnt == n - 1 or n <= 1 else None

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
    assert bottleneck(3, [(0, 1, 1), (1, 2, 2), (0, 2, 3)]) == 2
    assert bottleneck(4, [(0, 1, 5), (1, 2, 1), (2, 3, 4), (0, 3, 2)]) == 4
    assert bottleneck(1, []) == 0
    assert bottleneck(3, [(0, 1, 1)]) is None
    assert stdlib_only()
    print("mst-33 OK")


if __name__ == "__main__":
    main()
