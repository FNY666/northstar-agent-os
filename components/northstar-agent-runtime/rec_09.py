"""Linked-list reversal: tail-recursive with accumulator

Threads an accumulator through the recursion; each node is visited once.

What this IS: a real recursive list reversal over tuple lists.
What this IS NOT: a substitute for iterative host code; the host picks the algorithm.
"""

from __future__ import annotations

import ast

#: Module version.
REC_09_VERSION = "rec-ll-reverse.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.rec-ll-reverse.v1"


class RecError(Exception):
    """Fail-closed."""


#: Linked list: (value, rest); None is empty.
def to_ll(xs):
    """Build a tuple list from a Python list."""
    out = None
    for x in reversed(xs):
        out = (x, out)
    return out
def rev(lst, acc=None):
    """Reverse tuple list."""
    if lst is None:
        return acc
    v, rest = lst
    return rev(rest, (v, acc))


def to_py(lst):
    out = []
    while lst is not None:
        v, lst = lst
        out.append(v)
    return out

def test_rev_empty():
    assert to_py(rev(None)) == []


def test_rev_basic():
    assert to_py(rev(to_ll([1, 2, 3]))) == [3, 2, 1]


def test_rev_single():
    assert to_py(rev(to_ll([7]))) == [7]

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
    test_rev_empty()
    test_rev_basic()
    test_rev_single()
    assert stdlib_only()
    print("rec-ll-reverse OK")


if __name__ == "__main__":
    main()
