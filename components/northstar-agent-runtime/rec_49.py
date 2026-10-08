"""Tree sum: value + sum(left) + sum(right)

Adds every node value exactly once.

What this IS: a real recursive tree sum.
What this IS NOT: a substitute for iterative host code; the host picks the algorithm.
"""

from __future__ import annotations

import ast

#: Module version.
REC_49_VERSION = "rec-tree-sum.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.rec-tree-sum.v1"


class RecError(Exception):
    """Fail-closed."""


#: Binary tree node: (value, left, right); None is empty.
SAMPLE = (1, (2, (4, None, None), (5, None, None)), (3, None, (6, None, None)))
def tree_sum(t):
    """Sum of values in tuple tree."""
    if t is None:
        return 0
    v, l, r = t
    return v + tree_sum(l) + tree_sum(r)

def test_tree_sum_empty():
    assert tree_sum(None) == 0


def test_tree_sum_single():
    assert tree_sum((9, None, None)) == 9


def test_tree_sum_sample():
    assert tree_sum(SAMPLE) == 21

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
    test_tree_sum_empty()
    test_tree_sum_single()
    test_tree_sum_sample()
    assert stdlib_only()
    print("rec-tree-sum OK")


if __name__ == "__main__":
    main()
