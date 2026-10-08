"""Bipartite disjoint union.

What this IS: disjoint union of two bipartite graphs with shifted indices, fail-closed
What this IS NOT: a heuristic; exact index shifting
"""

from __future__ import annotations

import ast

#: Module version.
BIP_45_VERSION = "bip-disjoint-union.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.bip-disjoint-union.v1"


class BipError(Exception):
    """Fail-closed."""



def disjoint_union(nl1, nr1, e1, nl2, nr2, e2) -> tuple:
    for u, v in e1:
        if not (0 <= u < nl1 and 0 <= v < nr1):
            raise BipError("edge out of range (g1)")
    for u, v in e2:
        if not (0 <= u < nl2 and 0 <= v < nr2):
            raise BipError("edge out of range (g2)")
    shifted = [(u + nl1, v + nr1) for u, v in e2]
    return nl1 + nl2, nr1 + nr2, sorted(set(e1) | set(shifted))


def test_du_basic():
    nl, nr, e = disjoint_union(1, 1, [(0, 0)], 1, 1, [(0, 0)])
    assert (nl, nr, e) == (2, 2, [(0, 0), (1, 1)])


def test_du_empty():
    assert disjoint_union(2, 2, [], 1, 1, []) == (3, 3, [])


def test_du_sizes():
    nl, nr, e = disjoint_union(2, 1, [(0, 0), (1, 0)], 3, 2, [(2, 1)])
    assert nl == 5 and nr == 3 and (4, 2) in e


def test_du_bad():
    try:
        disjoint_union(1, 1, [(0, 0)], 1, 1, [(0, 5)])
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
    test_du_basic()
    test_du_empty()
    test_du_sizes()
    test_du_bad()
    assert stdlib_only()
    print("bip-45 OK: disjoint union")


if __name__ == "__main__":
    main()
