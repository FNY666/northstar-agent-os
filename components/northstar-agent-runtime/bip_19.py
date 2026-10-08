"""Bipartite density.

What this IS: edge density relative to the complete bipartite graph, fail-closed on bad input
What this IS NOT: general graph density; normalized by |L|*|R| here
"""

from __future__ import annotations

import ast

#: Module version.
BIP_19_VERSION = "bip-density.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.bip-density.v1"


class BipError(Exception):
    """Fail-closed."""



def density(n_left: int, n_right: int, edges: list) -> float:
    for u, v in edges:
        if not (0 <= u < n_left and 0 <= v < n_right):
            raise BipError("edge out of range")
    total = n_left * n_right
    if total == 0:
        return 0.0
    return len(set(edges)) / total


def test_density_k22():
    assert density(2, 2, [(0, 0), (0, 1), (1, 0), (1, 1)]) == 1.0


def test_density_half():
    assert density(2, 2, [(0, 0), (1, 1)]) == 0.5


def test_density_empty():
    assert density(3, 4, []) == 0.0


def test_density_bad():
    try:
        density(2, 2, [(0, 9)])
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
    test_density_k22()
    test_density_half()
    test_density_empty()
    test_density_bad()
    assert stdlib_only()
    print("bip-19 OK: density")


if __name__ == "__main__":
    main()
