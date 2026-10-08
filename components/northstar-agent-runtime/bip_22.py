"""Bipartite spanning forest.

What this IS: Kruskal-style spanning forest of the underlying undirected graph, fail-closed
What this IS NOT: a minimum spanning tree; unweighted so any spanning forest
"""

from __future__ import annotations

import ast

#: Module version.
BIP_22_VERSION = "bip-spanning-forest.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.bip-spanning-forest.v1"


class BipError(Exception):
    """Fail-closed."""



def spanning_forest(n: int, edges: list) -> list:
    for u, v in edges:
        if not (0 <= u < n and 0 <= v < n):
            raise BipError("edge out of range")
    parent = list(range(n))

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    forest = []
    for u, v in edges:
        ru, rv = find(u), find(v)
        if ru != rv:
            parent[ru] = rv
            forest.append((u, v))
    return forest


def test_forest_tree():
    f = spanning_forest(4, [(0, 1), (1, 2), (2, 3), (0, 3)])
    assert len(f) == 3


def test_forest_disconnected():
    f = spanning_forest(4, [(0, 1), (2, 3)])
    assert len(f) == 2


def test_forest_empty():
    assert spanning_forest(3, []) == []


def test_forest_bad():
    try:
        spanning_forest(2, [(0, 2)])
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
    test_forest_tree()
    test_forest_disconnected()
    test_forest_empty()
    test_forest_bad()
    assert stdlib_only()
    print("bip-22 OK: spanning forest")


if __name__ == "__main__":
    main()
