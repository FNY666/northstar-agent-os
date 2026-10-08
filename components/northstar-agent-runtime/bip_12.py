"""Biclique verification.

What this IS: verifies a vertex subset induces a complete bipartite subgraph, fail-closed on bad input
What this IS NOT: biclique enumeration; verification of a given candidate is exact
"""

from __future__ import annotations

import ast

#: Module version.
BIP_12_VERSION = "bip-biclique-check.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.bip-biclique-check.v1"


class BipError(Exception):
    """Fail-closed."""



def is_biclique(n_left: int, n_right: int, edges: list, left_set: list, right_set: list) -> bool:
    eset = set()
    for u, v in edges:
        if not (0 <= u < n_left and 0 <= v < n_right):
            raise BipError("edge out of range")
        eset.add((u, v))
    ls = set(left_set)
    rs = set(right_set)
    if not all(0 <= u < n_left for u in ls) or not all(0 <= v < n_right for v in rs):
        raise BipError("set out of range")
    return all((u, v) in eset for u in ls for v in rs)


def test_biclique_yes():
    assert is_biclique(2, 2, [(0, 0), (0, 1), (1, 0), (1, 1)], [0, 1], [0, 1])


def test_biclique_no():
    assert not is_biclique(2, 2, [(0, 0), (1, 1)], [0, 1], [0, 1])


def test_biclique_single():
    assert is_biclique(3, 3, [(1, 2)], [1], [2])


def test_biclique_bad():
    try:
        is_biclique(2, 2, [(0, 9)], [0], [0])
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
    test_biclique_yes()
    test_biclique_no()
    test_biclique_single()
    test_biclique_bad()
    assert stdlib_only()
    print("bip-12 OK: biclique verification")


if __name__ == "__main__":
    main()
