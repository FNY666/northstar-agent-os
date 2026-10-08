"""Preorder traversal: root-left-right by recursion

Visits the node before its children. O(n) time.

What this IS: a real recursive preorder traversal over tuple trees.
What this IS NOT: a substitute for iterative host code; the host picks the algorithm.
"""

from __future__ import annotations

import ast

#: Module version.
REC_04_VERSION = "rec-preorder.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.rec-preorder.v1"


class RecError(Exception):
    """Fail-closed."""


#: Binary tree node: (value, left, right); None is empty.
SAMPLE = (1, (2, (4, None, None), (5, None, None)), (3, None, (6, None, None)))
def preorder(t):
    """Root, left, right."""
    if t is None:
        return []
    v, l, r = t
    return [v] + preorder(l) + preorder(r)

def test_preorder_empty():
    assert preorder(None) == []


def test_preorder_sample():
    assert preorder(SAMPLE) == [1, 2, 4, 5, 3, 6]


def test_preorder_single():
    assert preorder((9, None, None)) == [9]

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
    test_preorder_empty()
    test_preorder_sample()
    test_preorder_single()
    assert stdlib_only()
    print("rec-preorder OK")


if __name__ == "__main__":
    main()
