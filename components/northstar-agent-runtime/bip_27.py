"""Bipartite adjacency matrix.

What this IS: builds the biadjacency matrix, fail-closed on bad input
What this IS NOT: a sparse representation; dense matrix here
"""

from __future__ import annotations

import ast

#: Module version.
BIP_27_VERSION = "bip-adj-matrix.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.bip-adj-matrix.v1"


class BipError(Exception):
    """Fail-closed."""



def biadjacency(n_left: int, n_right: int, edges: list) -> list:
    m = [[0] * n_right for _ in range(n_left)]
    for u, v in edges:
        if not (0 <= u < n_left and 0 <= v < n_right):
            raise BipError("edge out of range")
        m[u][v] = 1
    return m


def test_bm_k22():
    assert biadjacency(2, 2, [(0, 0), (0, 1), (1, 0), (1, 1)]) == [[1, 1], [1, 1]]


def test_bm_empty():
    assert biadjacency(2, 3, []) == [[0, 0, 0], [0, 0, 0]]


def test_bm_single():
    assert biadjacency(1, 1, [(0, 0)]) == [[1]]


def test_bm_bad():
    try:
        biadjacency(2, 2, [(2, 0)])
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
    test_bm_k22()
    test_bm_empty()
    test_bm_single()
    test_bm_bad()
    assert stdlib_only()
    print("bip-27 OK: adjacency matrix")


if __name__ == "__main__":
    main()
