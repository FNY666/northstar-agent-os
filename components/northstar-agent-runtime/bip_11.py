"""Bipartite complement.

What this IS: computes the bipartite complement edges, fail-closed on non-bipartite input
What this IS NOT: the general graph complement; only cross-partition non-edges are returned
"""

from __future__ import annotations

import ast

#: Module version.
BIP_11_VERSION = "bip-bip-complement.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.bip-bip-complement.v1"


class BipError(Exception):
    """Fail-closed."""



def bipartite_complement(n_left: int, n_right: int, edges: list) -> list:
    eset = set()
    for u, v in edges:
        if not (0 <= u < n_left and 0 <= v < n_right):
            raise BipError("edge out of range")
        eset.add((u, v))
    return [(u, v) for u in range(n_left) for v in range(n_right) if (u, v) not in eset]


def test_complement_k22():
    assert bipartite_complement(2, 2, [(0, 0), (0, 1), (1, 0), (1, 1)]) == []


def test_complement_empty():
    c = bipartite_complement(2, 2, [])
    assert len(c) == 4


def test_complement_partial():
    c = bipartite_complement(2, 2, [(0, 0)])
    assert sorted(c) == [(0, 1), (1, 0), (1, 1)]


def test_complement_bad():
    try:
        bipartite_complement(2, 2, [(0, 4)])
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
    test_complement_k22()
    test_complement_empty()
    test_complement_partial()
    test_complement_bad()
    assert stdlib_only()
    print("bip-11 OK: bipartite complement")


if __name__ == "__main__":
    main()
