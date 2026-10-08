"""Tree equality: values and shapes match

Both empty is equal; otherwise values and both subtrees must match.

What this IS: a real recursive structural equality check.
What this IS NOT: a substitute for iterative host code; the host picks the algorithm.
"""

from __future__ import annotations

import ast

#: Module version.
REC_27_VERSION = "rec-trees-equal.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.rec-trees-equal.v1"


class RecError(Exception):
    """Fail-closed."""


#: Binary tree node: (value, left, right); None is empty.
SAMPLE = (1, (2, (4, None, None), (5, None, None)), (3, None, (6, None, None)))
def trees_equal(a, b) -> bool:
    """Structural equality of tuple trees."""
    if a is None or b is None:
        return a is b
    va, la, ra = a
    vb, lb, rb = b
    return va == vb and trees_equal(la, lb) and trees_equal(ra, rb)

def test_equal_same():
    assert trees_equal(SAMPLE, SAMPLE) is True


def test_equal_empty():
    assert trees_equal(None, None) is True


def test_equal_mismatch():
    other = (1, (2, None, None), None)
    assert trees_equal(SAMPLE, other) is False


def test_equal_one_empty():
    assert trees_equal(SAMPLE, None) is False

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
    test_equal_same()
    test_equal_empty()
    test_equal_mismatch()
    test_equal_one_empty()
    assert stdlib_only()
    print("rec-trees-equal OK")


if __name__ == "__main__":
    main()
