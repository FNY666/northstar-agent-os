"""Bipartite vertex cover verification.

What this IS: verifies a candidate vertex cover, fail-closed on bad input
What this IS NOT: a minimum cover; verification of a candidate only
"""

from __future__ import annotations

import ast

#: Module version.
BIP_35_VERSION = "bip-cover-verify.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.bip-cover-verify.v1"


class BipError(Exception):
    """Fail-closed."""



def is_vertex_cover(n_left: int, n_right: int, edges: list, cl: list, cr: list) -> bool:
    sl = set(cl)
    sr = set(cr)
    if not all(0 <= u < n_left for u in sl) or not all(0 <= v < n_right for v in sr):
        raise BipError("cover out of range")
    for u, v in edges:
        if not (0 <= u < n_left and 0 <= v < n_right):
            raise BipError("edge out of range")
        if u not in sl and v not in sr:
            return False
    return True


def test_vc_yes():
    assert is_vertex_cover(2, 2, [(0, 0), (1, 1)], [0, 1], [])


def test_vc_no():
    assert not is_vertex_cover(2, 2, [(0, 0), (1, 1)], [0], [])


def test_vc_right():
    assert is_vertex_cover(2, 2, [(0, 0), (1, 0)], [], [0])


def test_vc_bad():
    try:
        is_vertex_cover(1, 1, [(0, 0)], [3], [])
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
    test_vc_yes()
    test_vc_no()
    test_vc_right()
    test_vc_bad()
    assert stdlib_only()
    print("bip-35 OK: cover verification")


if __name__ == "__main__":
    main()
