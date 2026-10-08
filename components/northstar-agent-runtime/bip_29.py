"""Bipartite neighborhood.

What this IS: neighbor set of a left vertex, fail-closed on bad input
What this IS NOT: 2-hop neighborhood; direct neighbors only
"""

from __future__ import annotations

import ast

#: Module version.
BIP_29_VERSION = "bip-neighborhood.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.bip-neighborhood.v1"


class BipError(Exception):
    """Fail-closed."""



def neighbors(n_left: int, n_right: int, edges: list, u: int) -> list:
    if not (0 <= u < n_left):
        raise BipError("vertex out of range")
    out = set()
    for a, b in edges:
        if not (0 <= a < n_left and 0 <= b < n_right):
            raise BipError("edge out of range")
        if a == u:
            out.add(b)
    return sorted(out)


def test_nbr_basic():
    assert neighbors(2, 3, [(0, 0), (0, 2)], 0) == [0, 2]


def test_nbr_empty():
    assert neighbors(2, 2, [(1, 1)], 0) == []


def test_nbr_all():
    assert neighbors(1, 3, [(0, 0), (0, 1), (0, 2)], 0) == [0, 1, 2]


def test_nbr_bad():
    try:
        neighbors(2, 2, [], 7)
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
    test_nbr_basic()
    test_nbr_empty()
    test_nbr_all()
    test_nbr_bad()
    assert stdlib_only()
    print("bip-29 OK: neighborhood")


if __name__ == "__main__":
    main()
