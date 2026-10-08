"""Bottleneck via threshold binary search + union-find (MST-034), Real."""
from __future__ import annotations
import ast

VERSION = "mst-34.v1"

def bottleneck_search(n, edges):
    ed = [(u, v, w) for u, v, w in edges if u != v]
    if n <= 1:
        return 0
    weights = sorted({w for _, _, w in ed})
    def connected(limit):
        parent = list(range(n))
        def find(x):
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x
        for u, v, w in ed:
            if w <= limit:
                ru, rv = find(u), find(v)
                if ru != rv:
                    parent[rv] = ru
        r = find(0)
        return all(find(i) == r for i in range(n))
    for w in weights:
        if connected(w):
            return w
    return None

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
    assert bottleneck_search(3, [(0, 1, 1), (1, 2, 2), (0, 2, 3)]) == 2
    assert bottleneck_search(4, [(0, 1, 5), (1, 2, 1), (2, 3, 4), (0, 3, 2)]) == 4
    assert bottleneck_search(3, [(0, 1, 1)]) is None
    assert stdlib_only()
    print("mst-34 OK")


if __name__ == "__main__":
    main()
