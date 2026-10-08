"""Bipartite neighborhood union size.

What this IS: size of the union of neighborhoods of a left subset, fail-closed
What this IS NOT: a heuristic; exact union computation
"""

from __future__ import annotations

import ast

#: Module version.
BIP_39_VERSION = "bip-nbr-union.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.bip-nbr-union.v1"


class BipError(Exception):
    """Fail-closed."""



def neighborhood_union_size(n_left: int, n_right: int, edges: list, subset: list) -> int:
    s = set(subset)
    if not all(0 <= u < n_left for u in s):
        raise BipError("subset out of range")
    union = set()
    for u, v in edges:
        if not (0 <= u < n_left and 0 <= v < n_right):
            raise BipError("edge out of range")
        if u in s:
            union.add(v)
    return len(union)


def test_nu_basic():
    assert neighborhood_union_size(2, 3, [(0, 0), (0, 1), (1, 2)], [0, 1]) == 3


def test_nu_overlap():
    assert neighborhood_union_size(2, 2, [(0, 0), (1, 0)], [0, 1]) == 1


def test_nu_empty():
    assert neighborhood_union_size(2, 2, [(0, 0)], []) == 0


def test_nu_bad():
    try:
        neighborhood_union_size(2, 2, [], [4])
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
    test_nu_basic()
    test_nu_overlap()
    test_nu_empty()
    test_nu_bad()
    assert stdlib_only()
    print("bip-39 OK: neighborhood union")


if __name__ == "__main__":
    main()
