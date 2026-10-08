"""Inorder traversal: left-root-right by recursion

Visits left subtree, node, right subtree. O(n) time.

What this IS: a real recursive inorder traversal over tuple trees.
What this IS NOT: a substitute for iterative host code; the host picks the algorithm.
"""

from __future__ import annotations

import ast

#: Module version.
REC_05_VERSION = "rec-inorder.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.rec-inorder.v1"


class RecError(Exception):
    """Fail-closed."""


#: Binary tree node: (value, left, right); None is empty.
SAMPLE = (1, (2, (4, None, None), (5, None, None)), (3, None, (6, None, None)))
def inorder(t):
    """Left, root, right."""
    if t is None:
        return []
    v, l, r = t
    return inorder(l) + [v] + inorder(r)

def test_inorder_empty():
    assert inorder(None) == []


def test_inorder_sample():
    assert inorder(SAMPLE) == [4, 2, 5, 1, 3, 6]


def test_inorder_single():
    assert inorder((9, None, None)) == [9]

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
    test_inorder_empty()
    test_inorder_sample()
    test_inorder_single()
    assert stdlib_only()
    print("rec-inorder OK")


if __name__ == "__main__":
    main()
