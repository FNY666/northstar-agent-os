"""Linked-list length: 1 + length(rest)

Direct structural recursion over the tuple list.

What this IS: a real recursive length over tuple lists.
What this IS NOT: a substitute for iterative host code; the host picks the algorithm.
"""

from __future__ import annotations

import ast

#: Module version.
REC_10_VERSION = "rec-ll-length.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.rec-ll-length.v1"


class RecError(Exception):
    """Fail-closed."""


#: Linked list: (value, rest); None is empty.
def to_ll(xs):
    """Build a tuple list from a Python list."""
    out = None
    for x in reversed(xs):
        out = (x, out)
    return out
def length(lst) -> int:
    """Length of tuple list."""
    if lst is None:
        return 0
    _, rest = lst
    return 1 + length(rest)

def test_length_empty():
    assert length(None) == 0


def test_length_basic():
    assert length(to_ll([1, 2, 3, 4])) == 4


def test_length_single():
    assert length(to_ll([7])) == 1

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
    test_length_empty()
    test_length_basic()
    test_length_single()
    assert stdlib_only()
    print("rec-ll-length OK")


if __name__ == "__main__":
    main()
