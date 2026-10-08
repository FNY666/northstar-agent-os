"""Bipartite Hall violator search.

What this IS: brute-force search for a Hall violator subset, fail-closed on bad input
What this IS NOT: a polynomial Hall check; exponential brute force for small graphs
"""

from __future__ import annotations

import ast

#: Module version.
BIP_38_VERSION = "bip-hall-violator.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.bip-hall-violator.v1"


class BipError(Exception):
    """Fail-closed."""



def hall_violator(n_left: int, n_right: int, edges: list):
    from itertools import combinations
    for u, v in edges:
        if not (0 <= u < n_left and 0 <= v < n_right):
            raise BipError("edge out of range")
    nbr = [set() for _ in range(n_left)]
    for u, v in edges:
        nbr[u].add(v)
    verts = list(range(n_left))
    for r in range(1, n_left + 1):
        for combo in combinations(verts, r):
            union = set()
            for u in combo:
                union |= nbr[u]
            if len(union) < len(combo):
                return sorted(combo)
    return None


def test_hall_ok():
    assert hall_violator(2, 2, [(0, 0), (0, 1), (1, 0), (1, 1)]) is None


def test_hall_violation():
    v = hall_violator(3, 2, [(0, 0), (1, 0), (2, 1)])
    assert v == [0, 1]


def test_hall_empty():
    assert hall_violator(0, 2, []) is None


def test_hall_bad():
    try:
        hall_violator(1, 1, [(0, 2)])
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
    test_hall_ok()
    test_hall_violation()
    test_hall_empty()
    test_hall_bad()
    assert stdlib_only()
    print("bip-38 OK: Hall violator")


if __name__ == "__main__":
    main()
