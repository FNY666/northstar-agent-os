"""Bipartite common neighbors.

What this IS: common right-neighbors of two left vertices, fail-closed on bad input
What this IS NOT: Jaccard similarity; raw intersection here
"""

from __future__ import annotations

import ast

#: Module version.
BIP_28_VERSION = "bip-common-nbrs.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.bip-common-nbrs.v1"


class BipError(Exception):
    """Fail-closed."""



def common_neighbors(n_left: int, n_right: int, edges: list, a: int, b: int) -> list:
    if not (0 <= a < n_left and 0 <= b < n_left):
        raise BipError("vertex out of range")
    nbr = [set() for _ in range(n_left)]
    for u, v in edges:
        if not (0 <= u < n_left and 0 <= v < n_right):
            raise BipError("edge out of range")
        nbr[u].add(v)
    return sorted(nbr[a] & nbr[b])


def test_cn_two():
    assert common_neighbors(2, 3, [(0, 0), (0, 1), (1, 1), (1, 2)], 0, 1) == [1]


def test_cn_none():
    assert common_neighbors(2, 2, [(0, 0), (1, 1)], 0, 1) == []


def test_cn_self():
    assert common_neighbors(2, 2, [(0, 0), (0, 1)], 0, 0) == [0, 1]


def test_cn_bad():
    try:
        common_neighbors(2, 2, [], 0, 5)
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
    test_cn_two()
    test_cn_none()
    test_cn_self()
    test_cn_bad()
    assert stdlib_only()
    print("bip-28 OK: common neighbors")


if __name__ == "__main__":
    main()
