"""Bipartite adjacency lists.

What this IS: builds sorted adjacency lists for both sides, fail-closed on bad input
What this IS NOT: a matrix; adjacency lists here
"""

from __future__ import annotations

import ast

#: Module version.
BIP_42_VERSION = "bip-adj-lists.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.bip-adj-lists.v1"


class BipError(Exception):
    """Fail-closed."""



def adjacency_lists(n_left: int, n_right: int, edges: list) -> tuple:
    al = [[] for _ in range(n_left)]
    ar = [[] for _ in range(n_right)]
    for u, v in edges:
        if not (0 <= u < n_left and 0 <= v < n_right):
            raise BipError("edge out of range")
        al[u].append(v)
        ar[v].append(u)
    return ([sorted(a) for a in al], [sorted(a) for a in ar])


def test_al_basic():
    al, ar = adjacency_lists(2, 2, [(0, 1), (1, 0)])
    assert al == [[1], [0]] and ar == [[1], [0]]


def test_al_empty():
    assert adjacency_lists(2, 2, []) == ([[], []], [[], []])


def test_al_multi():
    al, ar = adjacency_lists(1, 3, [(0, 2), (0, 0)])
    assert al == [[0, 2]] and ar == [[0], [], [0]]


def test_al_bad():
    try:
        adjacency_lists(2, 2, [(0, 2)])
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
    test_al_basic()
    test_al_empty()
    test_al_multi()
    test_al_bad()
    assert stdlib_only()
    print("bip-42 OK: adjacency lists")


if __name__ == "__main__":
    main()
