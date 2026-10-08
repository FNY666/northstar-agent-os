"""Bipartite matching verification.

What this IS: verifies a candidate matching, fail-closed on bad input
What this IS NOT: a maximum matching; verification of a candidate only
"""

from __future__ import annotations

import ast

#: Module version.
BIP_37_VERSION = "bip-matching-verify.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.bip-matching-verify.v1"


class BipError(Exception):
    """Fail-closed."""



def is_matching(n_left: int, n_right: int, edges: list, match: list) -> bool:
    eset = set()
    for u, v in edges:
        if not (0 <= u < n_left and 0 <= v < n_right):
            raise BipError("edge out of range")
        eset.add((u, v))
    seen_l, seen_r = set(), set()
    for u, v in match:
        if (u, v) not in eset:
            return False
        if u in seen_l or v in seen_r:
            return False
        seen_l.add(u)
        seen_r.add(v)
    return True


def test_mt_yes():
    assert is_matching(2, 2, [(0, 0), (1, 1)], [(0, 0), (1, 1)])


def test_mt_conflict():
    assert not is_matching(2, 2, [(0, 0), (0, 1)], [(0, 0), (0, 1)])


def test_mt_nonedge():
    assert not is_matching(2, 2, [(0, 0)], [(1, 1)])


def test_mt_bad():
    try:
        is_matching(1, 1, [(0, 9)], [])
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
    test_mt_yes()
    test_mt_conflict()
    test_mt_nonedge()
    test_mt_bad()
    assert stdlib_only()
    print("bip-37 OK: matching verification")


if __name__ == "__main__":
    main()
