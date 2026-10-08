"""Bipartite one-mode projection.

What this IS: projects onto left vertices: edge when sharing a right neighbor, fail-closed on bad input
What this IS NOT: a lossy projection; weights count shared neighbors
"""

from __future__ import annotations

import ast

#: Module version.
BIP_20_VERSION = "bip-projection.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.bip-projection.v1"


class BipError(Exception):
    """Fail-closed."""



def project_left(n_left: int, n_right: int, edges: list) -> dict:
    nbr = [set() for _ in range(n_left)]
    for u, v in edges:
        if not (0 <= u < n_left and 0 <= v < n_right):
            raise BipError("edge out of range")
        nbr[u].add(v)
    proj = {}
    for a in range(n_left):
        for b in range(a + 1, n_left):
            w = len(nbr[a] & nbr[b])
            if w:
                proj[(a, b)] = w
    return proj


def test_proj_k22():
    assert project_left(2, 2, [(0, 0), (0, 1), (1, 0), (1, 1)]) == {(0, 1): 2}


def test_proj_disjoint():
    assert project_left(2, 2, [(0, 0), (1, 1)]) == {}


def test_proj_chain():
    p = project_left(3, 2, [(0, 0), (1, 0), (1, 1), (2, 1)])
    assert p == {(0, 1): 1, (1, 2): 1}


def test_proj_bad():
    try:
        project_left(1, 1, [(1, 0)])
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
    test_proj_k22()
    test_proj_disjoint()
    test_proj_chain()
    test_proj_bad()
    assert stdlib_only()
    print("bip-20 OK: one-mode projection")


if __name__ == "__main__":
    main()
