"""Bipartite degree sequences.

What this IS: computes left/right degree sequences, fail-closed on bad input
What this IS NOT: graphic-sequence testing; raw degrees only
"""

from __future__ import annotations

import ast

#: Module version.
BIP_13_VERSION = "bip-degree-seq.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.bip-degree-seq.v1"


class BipError(Exception):
    """Fail-closed."""



def degree_sequences(n_left: int, n_right: int, edges: list) -> tuple:
    dl = [0] * n_left
    dr = [0] * n_right
    for u, v in edges:
        if not (0 <= u < n_left and 0 <= v < n_right):
            raise BipError("edge out of range")
        dl[u] += 1
        dr[v] += 1
    return sorted(dl, reverse=True), sorted(dr, reverse=True)


def test_deg_k23():
    dl, dr = degree_sequences(2, 3, [(a, b) for a in range(2) for b in range(3)])
    assert dl == [3, 3] and dr == [2, 2, 2]


def test_deg_empty():
    assert degree_sequences(2, 2, []) == ([0, 0], [0, 0])


def test_deg_sums_equal():
    dl, dr = degree_sequences(3, 4, [(0, 0), (1, 2), (2, 3)])
    assert sum(dl) == sum(dr) == 3


def test_deg_bad():
    try:
        degree_sequences(2, 2, [(5, 0)])
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
    test_deg_k23()
    test_deg_empty()
    test_deg_sums_equal()
    test_deg_bad()
    assert stdlib_only()
    print("bip-13 OK: degree sequences")


if __name__ == "__main__":
    main()
