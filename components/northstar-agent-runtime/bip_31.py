"""Bipartite pendant vertices.

What this IS: lists degree-1 vertices on both sides, fail-closed on bad input
What this IS NOT: a heuristic; exact degree-one scan
"""

from __future__ import annotations

import ast

#: Module version.
BIP_31_VERSION = "bip-pendants.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.bip-pendants.v1"


class BipError(Exception):
    """Fail-closed."""



def pendants(n_left: int, n_right: int, edges: list) -> tuple:
    dl = [0] * n_left
    dr = [0] * n_right
    for u, v in edges:
        if not (0 <= u < n_left and 0 <= v < n_right):
            raise BipError("edge out of range")
        dl[u] += 1
        dr[v] += 1
    return ([u for u in range(n_left) if dl[u] == 1],
            [v for v in range(n_right) if dr[v] == 1])


def test_pend_star():
    assert pendants(1, 3, [(0, 0), (0, 1), (0, 2)]) == ([], [0, 1, 2])


def test_pend_none():
    assert pendants(2, 2, [(0, 0), (0, 1), (1, 0), (1, 1)]) == ([], [])


def test_pend_path():
    assert pendants(2, 2, [(0, 0), (1, 0), (1, 1)]) == ([0], [1])


def test_pend_bad():
    try:
        pendants(2, 2, [(9, 0)])
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
    test_pend_star()
    test_pend_none()
    test_pend_path()
    test_pend_bad()
    assert stdlib_only()
    print("bip-31 OK: pendant vertices")


if __name__ == "__main__":
    main()
