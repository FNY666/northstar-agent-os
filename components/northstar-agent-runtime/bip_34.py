"""Bipartite domination check.

What this IS: checks whether a left subset dominates all right vertices, fail-closed
What this IS NOT: a minimum dominating set; verification of a candidate only
"""

from __future__ import annotations

import ast

#: Module version.
BIP_34_VERSION = "bip-dominating.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.bip-dominating.v1"


class BipError(Exception):
    """Fail-closed."""



def dominates(n_left: int, n_right: int, edges: list, subset: list) -> bool:
    s = set(subset)
    if not all(0 <= u < n_left for u in s):
        raise BipError("subset out of range")
    covered = set()
    for u, v in edges:
        if not (0 <= u < n_left and 0 <= v < n_right):
            raise BipError("edge out of range")
        if u in s:
            covered.add(v)
    return len(covered) == n_right


def test_dom_yes():
    assert dominates(2, 2, [(0, 0), (1, 1)], [0, 1])


def test_dom_no():
    assert not dominates(2, 2, [(0, 0), (1, 1)], [0])


def test_dom_empty_right():
    assert dominates(2, 0, [], [])


def test_dom_bad():
    try:
        dominates(1, 1, [(0, 0)], [5])
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
    test_dom_yes()
    test_dom_no()
    test_dom_empty_right()
    test_dom_bad()
    assert stdlib_only()
    print("bip-34 OK: domination check")


if __name__ == "__main__":
    main()
