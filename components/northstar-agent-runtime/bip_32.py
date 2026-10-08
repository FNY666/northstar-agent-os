"""Bipartite universal vertices.

What this IS: left vertices adjacent to every right vertex and vice versa, fail-closed
What this IS NOT: a heuristic; exact full-degree scan
"""

from __future__ import annotations

import ast

#: Module version.
BIP_32_VERSION = "bip-universal.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.bip-universal.v1"


class BipError(Exception):
    """Fail-closed."""



def universal(n_left: int, n_right: int, edges: list) -> tuple:
    dl = [0] * n_left
    dr = [0] * n_right
    for u, v in edges:
        if not (0 <= u < n_left and 0 <= v < n_right):
            raise BipError("edge out of range")
        dl[u] += 1
        dr[v] += 1
    return ([u for u in range(n_left) if dl[u] == n_right],
            [v for v in range(n_right) if dr[v] == n_left])


def test_univ_k22():
    assert universal(2, 2, [(0, 0), (0, 1), (1, 0), (1, 1)]) == ([0, 1], [0, 1])


def test_univ_none():
    assert universal(2, 2, [(0, 0)]) == ([], [])


def test_univ_one_side():
    assert universal(2, 2, [(0, 0), (0, 1)]) == ([0], [])


def test_univ_bad():
    try:
        universal(1, 1, [(0, 5)])
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
    test_univ_k22()
    test_univ_none()
    test_univ_one_side()
    test_univ_bad()
    assert stdlib_only()
    print("bip-32 OK: universal vertices")


if __name__ == "__main__":
    main()
