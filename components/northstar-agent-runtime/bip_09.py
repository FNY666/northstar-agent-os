"""Greedy bipartite matching.

What this IS: a fast greedy maximal matching, fail-closed on bad input
What this IS NOT: maximum; greedy is maximal but not always maximum
"""

from __future__ import annotations

import ast

#: Module version.
BIP_09_VERSION = "bip-greedy-matching.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.bip-greedy-matching.v1"


class BipError(Exception):
    """Fail-closed."""



def greedy_matching(n_left: int, n_right: int, edges: list) -> dict:
    for u, v in edges:
        if not (0 <= u < n_left and 0 <= v < n_right):
            raise BipError("edge out of range")
    used_l = [False] * n_left
    used_r = [False] * n_right
    m = {}
    for u, v in edges:
        if not used_l[u] and not used_r[v]:
            used_l[u] = True
            used_r[v] = True
            m[v] = u
    return m


def test_greedy_simple():
    m = greedy_matching(2, 2, [(0, 0), (1, 1)])
    assert len(m) == 2


def test_greedy_maximal():
    # greedy may miss the max on adversarial order, but must be maximal
    edges = [(0, 0), (0, 1), (1, 0)]
    m = greedy_matching(2, 2, edges)
    used_l = set(m.values())
    used_r = set(m.keys())
    for u, v in edges:
        assert u in used_l or v in used_r


def test_greedy_empty():
    assert greedy_matching(3, 3, []) == {}


def test_greedy_bad():
    try:
        greedy_matching(1, 1, [(0, 2)])
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
    test_greedy_simple()
    test_greedy_maximal()
    test_greedy_empty()
    test_greedy_bad()
    assert stdlib_only()
    print("bip-09 OK: greedy matching")


if __name__ == "__main__":
    main()
