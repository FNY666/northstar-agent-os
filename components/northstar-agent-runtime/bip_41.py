"""Bipartite edge list canonicalization.

What this IS: returns sorted unique edge list, fail-closed on bad input
What this IS NOT: a heuristic; exact dedup and sort
"""

from __future__ import annotations

import ast

#: Module version.
BIP_41_VERSION = "bip-canon-edges.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.bip-canon-edges.v1"


class BipError(Exception):
    """Fail-closed."""



def canonical_edges(n_left: int, n_right: int, edges: list) -> list:
    out = set()
    for u, v in edges:
        if not (0 <= u < n_left and 0 <= v < n_right):
            raise BipError("edge out of range")
        out.add((u, v))
    return sorted(out)


def test_ce_dup():
    assert canonical_edges(2, 2, [(1, 1), (0, 0), (1, 1)]) == [(0, 0), (1, 1)]


def test_ce_empty():
    assert canonical_edges(2, 2, []) == []


def test_ce_sorted():
    assert canonical_edges(3, 3, [(2, 2), (0, 1)]) == [(0, 1), (2, 2)]


def test_ce_bad():
    try:
        canonical_edges(1, 1, [(0, 1)])
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
    test_ce_dup()
    test_ce_empty()
    test_ce_sorted()
    test_ce_bad()
    assert stdlib_only()
    print("bip-41 OK: canonical edges")


if __name__ == "__main__":
    main()
