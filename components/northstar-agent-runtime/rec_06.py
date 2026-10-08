"""Postorder traversal: left-right-root by recursion

Visits children before the node. O(n) time.

What this IS: a real recursive postorder traversal over tuple trees.
What this IS NOT: a substitute for iterative host code; the host picks the algorithm.
"""

from __future__ import annotations

import ast

#: Module version.
REC_06_VERSION = "rec-postorder.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.rec-postorder.v1"


class RecError(Exception):
    """Fail-closed."""


#: Binary tree node: (value, left, right); None is empty.
SAMPLE = (1, (2, (4, None, None), (5, None, None)), (3, None, (6, None, None)))
def postorder(t):
    """Left, right, root."""
    if t is None:
        return []
    v, l, r = t
    return postorder(l) + postorder(r) + [v]

def test_postorder_empty():
    assert postorder(None) == []


def test_postorder_sample():
    assert postorder(SAMPLE) == [4, 5, 2, 6, 3, 1]


def test_postorder_single():
    assert postorder((9, None, None)) == [9]

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
    test_postorder_empty()
    test_postorder_sample()
    test_postorder_single()
    assert stdlib_only()
    print("rec-postorder OK")


if __name__ == "__main__":
    main()
