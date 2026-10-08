"""Bipartite check via union-find with parity.

What this IS: a genuine bipartiteness test using DSU with parity, fail-closed on bad input
What this IS NOT: BFS coloring; DSU-parity is exact and near-linear
"""

from __future__ import annotations

import ast

#: Module version.
BIP_08_VERSION = "bip-uf-parity.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.bip-uf-parity.v1"


class BipError(Exception):
    """Fail-closed."""



def is_bipartite_uf(n: int, edges: list) -> bool:
    parent = list(range(n))
    rank = [0] * n
    parity = [0] * n

    def find(x):
        if parent[x] != x:
            r = find(parent[x])
            parity[x] ^= parity[parent[x]]
            parent[x] = r
        return parent[x]

    def union(x, y):
        rx, ry = find(x), find(y)
        px, py = parity[x], parity[y]
        if rx == ry:
            return (px ^ py) == 1
        if rank[rx] < rank[ry]:
            rx, ry = ry, rx
            px, py = py, px
        parent[ry] = rx
        parity[ry] = px ^ py ^ 1
        if rank[rx] == rank[ry]:
            rank[rx] += 1
        return True

    for u, v in edges:
        if not (0 <= u < n and 0 <= v < n):
            raise BipError("edge out of range")
        if u == v:
            return False
        if not union(u, v):
            return False
    return True


def test_uf_square():
    assert is_bipartite_uf(4, [(0, 1), (1, 2), (2, 3), (3, 0)])


def test_uf_triangle():
    assert not is_bipartite_uf(3, [(0, 1), (1, 2), (2, 0)])


def test_uf_chain():
    assert is_bipartite_uf(5, [(0, 1), (1, 2), (2, 3), (3, 4)])


def test_uf_bad():
    try:
        is_bipartite_uf(2, [(0, 3)])
    except BipError:
        return
    raise AssertionError("expected BipError")



def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib", "collections", "heapq", "itertools", "functools", "math"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    """Self-check."""
    test_uf_square()
    test_uf_triangle()
    test_uf_chain()
    test_uf_bad()
    assert stdlib_only()
    print("bip-08 OK: union-find parity check")


if __name__ == "__main__":
    main()
