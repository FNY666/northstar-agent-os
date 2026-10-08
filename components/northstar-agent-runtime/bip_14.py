"""Biregular check.

What this IS: checks all left vertices share one degree and all right share another, fail-closed
What this IS NOT: regularity in general graphs; biregularity is the bipartite analogue
"""

from __future__ import annotations

import ast

#: Module version.
BIP_14_VERSION = "bip-biregular.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.bip-biregular.v1"


class BipError(Exception):
    """Fail-closed."""



def is_biregular(n_left: int, n_right: int, edges: list):
    dl = [0] * n_left
    dr = [0] * n_right
    for u, v in edges:
        if not (0 <= u < n_left and 0 <= v < n_right):
            raise BipError("edge out of range")
        dl[u] += 1
        dr[v] += 1
    if len(set(dl)) != 1 or len(set(dr)) != 1:
        return False, None
    return True, (dl[0], dr[0])


def test_biregular_k23():
    ok, degs = is_biregular(2, 3, [(a, b) for a in range(2) for b in range(3)])
    assert ok and degs == (3, 2)


def test_not_biregular():
    ok, _ = is_biregular(2, 2, [(0, 0), (0, 1)])
    assert not ok


def test_empty_biregular():
    ok, degs = is_biregular(2, 2, [])
    assert ok and degs == (0, 0)


def test_biregular_bad():
    try:
        is_biregular(1, 1, [(1, 0)])
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
    test_biregular_k23()
    test_not_biregular()
    test_empty_biregular()
    test_biregular_bad()
    assert stdlib_only()
    print("bip-14 OK: biregular check")


if __name__ == "__main__":
    main()
