"""Bipartite transpose.

What this IS: swaps the two sides, fail-closed on bad input
What this IS NOT: a heuristic; exact side swap
"""

from __future__ import annotations

import ast

#: Module version.
BIP_43_VERSION = "bip-transpose.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.bip-transpose.v1"


class BipError(Exception):
    """Fail-closed."""



def transpose(n_left: int, n_right: int, edges: list) -> tuple:
    for u, v in edges:
        if not (0 <= u < n_left and 0 <= v < n_right):
            raise BipError("edge out of range")
    return n_right, n_left, [(v, u) for u, v in edges]


def test_tr_basic():
    assert transpose(2, 3, [(0, 1), (1, 2)]) == (3, 2, [(1, 0), (2, 1)])


def test_tr_empty():
    assert transpose(2, 2, []) == (2, 2, [])


def test_tr_involution():
    nl, nr, e = transpose(2, 3, [(0, 0)])
    nl2, nr2, e2 = transpose(nl, nr, e)
    assert (nl2, nr2, e2) == (2, 3, [(0, 0)])


def test_tr_bad():
    try:
        transpose(1, 1, [(1, 0)])
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
    test_tr_basic()
    test_tr_empty()
    test_tr_involution()
    test_tr_bad()
    assert stdlib_only()
    print("bip-43 OK: transpose")


if __name__ == "__main__":
    main()
