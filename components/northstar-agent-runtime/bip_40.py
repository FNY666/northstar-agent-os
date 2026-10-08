"""Bipartite double counting check.

What this IS: verifies sum of left degrees equals sum of right degrees equals |E|, fail-closed
What this IS NOT: a heuristic; exact counting identity
"""

from __future__ import annotations

import ast

#: Module version.
BIP_40_VERSION = "bip-double-count.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.bip-double-count.v1"


class BipError(Exception):
    """Fail-closed."""



def check_double_count(n_left: int, n_right: int, edges: list) -> tuple:
    dl = [0] * n_left
    dr = [0] * n_right
    for u, v in edges:
        if not (0 <= u < n_left and 0 <= v < n_right):
            raise BipError("edge out of range")
        dl[u] += 1
        dr[v] += 1
    return sum(dl), sum(dr), len(edges)


def test_dc_basic():
    assert check_double_count(2, 3, [(0, 0), (1, 2)]) == (2, 2, 2)


def test_dc_empty():
    assert check_double_count(2, 2, []) == (0, 0, 0)


def test_dc_multi():
    s = check_double_count(3, 3, [(0, 0), (0, 1), (2, 2)])
    assert s[0] == s[1] == s[2] == 3


def test_dc_bad():
    try:
        check_double_count(1, 1, [(1, 0)])
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
    test_dc_basic()
    test_dc_empty()
    test_dc_multi()
    test_dc_bad()
    assert stdlib_only()
    print("bip-40 OK: double counting")


if __name__ == "__main__":
    main()
