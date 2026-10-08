"""BST insert: functional insertion

Returns a new tree; duplicates are ignored.

What this IS: a real recursive functional BST insert.
What this IS NOT: a substitute for iterative host code; the host picks the algorithm.
"""

from __future__ import annotations

import ast

#: Module version.
REC_32_VERSION = "rec-bst-insert.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.rec-bst-insert.v1"


class RecError(Exception):
    """Fail-closed."""


def bst_insert(t, x):
    """New BST with x inserted (duplicates ignored)."""
    if t is None:
        return (x, None, None)
    v, l, r = t
    if x == v:
        return t
    if x < v:
        return (v, bst_insert(l, x), r)
    return (v, l, bst_insert(r, x))


def bst_search(t, x) -> bool:
    if t is None:
        return False
    v, l, r = t
    if x == v:
        return True
    return bst_search(l, x) if x < v else bst_search(r, x)

def test_insert_empty():
    assert bst_insert(None, 5) == (5, None, None)


def test_insert_keeps_searchable():
    t = bst_insert(bst_insert(None, 4), 2)
    assert bst_search(t, 2) is True


def test_insert_duplicate():
    t = (4, None, None)
    assert bst_insert(t, 4) == t


def test_insert_order():
    t = None
    for x in (3, 1, 2):
        t = bst_insert(t, x)
    assert bst_search(t, 1) and bst_search(t, 2) and bst_search(t, 3)

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
    test_insert_empty()
    test_insert_keeps_searchable()
    test_insert_duplicate()
    test_insert_order()
    assert stdlib_only()
    print("rec-bst-insert OK")


if __name__ == "__main__":
    main()
