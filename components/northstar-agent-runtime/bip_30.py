"""Bipartite isolated vertices.

What this IS: lists isolated vertices on both sides, fail-closed on bad input
What this IS NOT: a heuristic; exact degree-zero scan
"""

from __future__ import annotations

import ast

#: Module version.
BIP_30_VERSION = "bip-isolates.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.bip-isolates.v1"


class BipError(Exception):
    """Fail-closed."""



def isolated(n_left: int, n_right: int, edges: list) -> tuple:
    dl = [0] * n_left
    dr = [0] * n_right
    for u, v in edges:
        if not (0 <= u < n_left and 0 <= v < n_right):
            raise BipError("edge out of range")
        dl[u] += 1
        dr[v] += 1
    return ([u for u in range(n_left) if dl[u] == 0],
            [v for v in range(n_right) if dr[v] == 0])


def test_iso_some():
    assert isolated(3, 2, [(0, 0)]) == ([1, 2], [1])


def test_iso_none():
    assert isolated(1, 1, [(0, 0)]) == ([], [])


def test_iso_all():
    assert isolated(2, 2, []) == ([0, 1], [0, 1])


def test_iso_bad():
    try:
        isolated(1, 1, [(0, 3)])
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
    test_iso_some()
    test_iso_none()
    test_iso_all()
    test_iso_bad()
    assert stdlib_only()
    print("bip-30 OK: isolated vertices")


if __name__ == "__main__":
    main()
