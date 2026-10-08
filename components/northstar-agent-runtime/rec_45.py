"""Leaf count: leaf = both children empty

A node with no children contributes 1; empty tree contributes 0.

What this IS: a real recursive leaf counter.
What this IS NOT: a substitute for iterative host code; the host picks the algorithm.
"""

from __future__ import annotations

import ast

#: Module version.
REC_45_VERSION = "rec-count-leaves.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.rec-count-leaves.v1"


class RecError(Exception):
    """Fail-closed."""


#: Binary tree node: (value, left, right); None is empty.
SAMPLE = (1, (2, (4, None, None), (5, None, None)), (3, None, (6, None, None)))
def count_leaves(t) -> int:
    """Leaf count of tuple tree."""
    if t is None:
        return 0
    _, l, r = t
    if l is None and r is None:
        return 1
    return count_leaves(l) + count_leaves(r)

def test_leaves_empty():
    assert count_leaves(None) == 0


def test_leaves_single():
    assert count_leaves((9, None, None)) == 1


def test_leaves_sample():
    assert count_leaves(SAMPLE) == 3

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
    test_leaves_empty()
    test_leaves_single()
    test_leaves_sample()
    assert stdlib_only()
    print("rec-count-leaves OK")


if __name__ == "__main__":
    main()
