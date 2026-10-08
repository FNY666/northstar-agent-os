"""Mirror check: left mirrors right

A tree is symmetric when left and right subtrees are mirrors of each other.

What this IS: a real recursive mirror/symmetry check.
What this IS NOT: a substitute for iterative host code; the host picks the algorithm.
"""

from __future__ import annotations

import ast

#: Module version.
REC_28_VERSION = "rec-tree-mirror.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.rec-tree-mirror.v1"


class RecError(Exception):
    """Fail-closed."""


#: Binary tree node: (value, left, right); None is empty.
SAMPLE = (1, (2, (4, None, None), (5, None, None)), (3, None, (6, None, None)))
def is_mirror(a, b) -> bool:
    """True when a mirrors b."""
    if a is None or b is None:
        return a is b
    va, la, ra = a
    vb, lb, rb = b
    return va == vb and is_mirror(la, rb) and is_mirror(ra, lb)


def is_symmetric(t) -> bool:
    """True when t is symmetric."""
    if t is None:
        return True
    _, l, r = t
    return is_mirror(l, r)

def test_symmetric_true():
    t = (1, (2, (3, None, None), None), (2, None, (3, None, None)))
    assert is_symmetric(t) is True


def test_symmetric_false():
    assert is_symmetric(SAMPLE) is False


def test_symmetric_empty():
    assert is_symmetric(None) is True


def test_symmetric_single():
    assert is_symmetric((9, None, None)) is True

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
    test_symmetric_true()
    test_symmetric_false()
    test_symmetric_empty()
    test_symmetric_single()
    assert stdlib_only()
    print("rec-tree-mirror OK")


if __name__ == "__main__":
    main()
