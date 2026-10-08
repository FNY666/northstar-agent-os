"""Bipartite twin vertices.

What this IS: groups left vertices with identical neighborhoods, fail-closed on bad input
What this IS NOT: a heuristic; exact neighborhood-equality grouping
"""

from __future__ import annotations

import ast

#: Module version.
BIP_33_VERSION = "bip-twins.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.bip-twins.v1"


class BipError(Exception):
    """Fail-closed."""



def twin_classes(n_left: int, n_right: int, edges: list) -> list:
    nbr = [set() for _ in range(n_left)]
    for u, v in edges:
        if not (0 <= u < n_left and 0 <= v < n_right):
            raise BipError("edge out of range")
        nbr[u].add(v)
    groups = {}
    for u in range(n_left):
        key = tuple(sorted(nbr[u]))
        groups.setdefault(key, []).append(u)
    return sorted([sorted(g) for g in groups.values()], key=lambda g: g[0])


def test_twin_same():
    assert twin_classes(3, 2, [(0, 0), (1, 0), (2, 1)]) == [[0, 1], [2]]


def test_twin_all_diff():
    assert twin_classes(2, 2, [(0, 0), (1, 1)]) == [[0], [1]]


def test_twin_empty():
    assert twin_classes(2, 2, []) == [[0, 1]]


def test_twin_bad():
    try:
        twin_classes(1, 1, [(0, 2)])
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
    test_twin_same()
    test_twin_all_diff()
    test_twin_empty()
    test_twin_bad()
    assert stdlib_only()
    print("bip-33 OK: twin vertices")


if __name__ == "__main__":
    main()
