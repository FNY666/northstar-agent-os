"""Bipartite induced subgraph.

What this IS: induces on left/right subsets, fail-closed on bad input
What this IS NOT: a heuristic; exact edge filtering
"""

from __future__ import annotations

import ast

#: Module version.
BIP_44_VERSION = "bip-induced.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.bip-induced.v1"


class BipError(Exception):
    """Fail-closed."""



def induced_subgraph(n_left: int, n_right: int, edges: list, ls: list, rs: list) -> list:
    L, R = set(ls), set(rs)
    if not all(0 <= u < n_left for u in L) or not all(0 <= v < n_right for v in R):
        raise BipError("subset out of range")
    out = []
    for u, v in edges:
        if not (0 <= u < n_left and 0 <= v < n_right):
            raise BipError("edge out of range")
        if u in L and v in R:
            out.append((u, v))
    return sorted(out)


def test_ind_basic():
    e = induced_subgraph(3, 3, [(0, 0), (1, 1), (2, 2)], [0, 1], [0, 1])
    assert e == [(0, 0), (1, 1)]


def test_ind_empty():
    assert induced_subgraph(2, 2, [(0, 0)], [1], [1]) == []


def test_ind_all():
    e = induced_subgraph(2, 2, [(0, 1)], [0, 1], [0, 1])
    assert e == [(0, 1)]


def test_ind_bad():
    try:
        induced_subgraph(2, 2, [(0, 0)], [9], [0])
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
    test_ind_basic()
    test_ind_empty()
    test_ind_all()
    test_ind_bad()
    assert stdlib_only()
    print("bip-44 OK: induced subgraph")


if __name__ == "__main__":
    main()
