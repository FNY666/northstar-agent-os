"""Bipartite edge count by partition.

What this IS: counts edges crossing the bipartition, fail-closed on non-bipartite input
What this IS NOT: a general edge counter; raises BipError when not bipartite
"""

from __future__ import annotations

import ast

#: Module version.
BIP_26_VERSION = "bip-edge-count.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.bip-edge-count.v1"


class BipError(Exception):
    """Fail-closed."""



def crossing_edges(n: int, edges: list, left: set) -> int:
    for u, v in edges:
        if not (0 <= u < n and 0 <= v < n):
            raise BipError("edge out of range")
    # verify bipartition: no edge inside one side
    for u, v in edges:
        if (u in left) == (v in left):
            raise BipError("not bipartite for given partition")
    return len(edges)


def test_ce_all():
    assert crossing_edges(4, [(0, 2), (0, 3), (1, 2)], {0, 1}) == 3


def test_ce_empty():
    assert crossing_edges(3, [], {0}) == 0


def test_ce_violation():
    try:
        crossing_edges(3, [(0, 1)], {0, 1})
    except BipError:
        return
    raise AssertionError("expected BipError")


def test_ce_bad():
    try:
        crossing_edges(2, [(0, 5)], {0})
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
    test_ce_all()
    test_ce_empty()
    test_ce_violation()
    test_ce_bad()
    assert stdlib_only()
    print("bip-26 OK: edge count")


if __name__ == "__main__":
    main()
