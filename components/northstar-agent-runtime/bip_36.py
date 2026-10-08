"""Bipartite independent set verification.

What this IS: verifies a candidate independent set, fail-closed on bad input
What this IS NOT: a maximum independent set; verification of a candidate only
"""

from __future__ import annotations

import ast

#: Module version.
BIP_36_VERSION = "bip-ind-verify.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.bip-ind-verify.v1"


class BipError(Exception):
    """Fail-closed."""



def is_independent_set(n_left: int, n_right: int, edges: list, il: list, ir: list) -> bool:
    sl = set(il)
    sr = set(ir)
    if not all(0 <= u < n_left for u in sl) or not all(0 <= v < n_right for v in sr):
        raise BipError("set out of range")
    eset = set()
    for u, v in edges:
        if not (0 <= u < n_left and 0 <= v < n_right):
            raise BipError("edge out of range")
        eset.add((u, v))
    return not any((u, v) in eset for u in sl for v in sr)


def test_is_yes():
    assert is_independent_set(2, 2, [(0, 0)], [1], [1])


def test_is_no():
    assert not is_independent_set(2, 2, [(0, 0)], [0], [0])


def test_is_empty_edges():
    assert is_independent_set(2, 2, [], [0, 1], [0, 1])


def test_is_bad():
    try:
        is_independent_set(1, 1, [(0, 0)], [9], [])
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
    test_is_yes()
    test_is_no()
    test_is_empty_edges()
    test_is_bad()
    assert stdlib_only()
    print("bip-36 OK: independent set verification")


if __name__ == "__main__":
    main()
