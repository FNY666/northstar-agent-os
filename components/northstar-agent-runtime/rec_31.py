"""BST search: go left or right by comparison

Requires the BST ordering invariant; O(h) time.

What this IS: a real recursive BST search.
What this IS NOT: a substitute for iterative host code; the host picks the algorithm.
"""

from __future__ import annotations

import ast

#: Module version.
REC_31_VERSION = "rec-bst-search.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.rec-bst-search.v1"


class RecError(Exception):
    """Fail-closed."""


def bst_search(t, x) -> bool:
    """True when x is in the BST tuple tree."""
    if t is None:
        return False
    v, l, r = t
    if x == v:
        return True
    if x < v:
        return bst_search(l, x)
    return bst_search(r, x)


BST = (4, (2, (1, None, None), (3, None, None)), (6, (5, None, None), (7, None, None)))

def test_bst_found():
    assert bst_search(BST, 5) is True


def test_bst_missing():
    assert bst_search(BST, 8) is False


def test_bst_empty():
    assert bst_search(None, 1) is False


def test_bst_root():
    assert bst_search(BST, 4) is True

def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib"}
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                if a.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(n, ast.ImportFrom):
            if n.module and n.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    test_bst_found()
    test_bst_missing()
    test_bst_empty()
    test_bst_root()
    assert stdlib_only()
    print("rec-bst-search OK")


if __name__ == "__main__":
    main()
