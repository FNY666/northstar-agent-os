"""Tree size: 1 + size(left) + size(right)

Counts every node exactly once. O(n) time.

What this IS: a real recursive node count.
What this IS NOT: a substitute for iterative host code; the host picks the algorithm.
"""

from __future__ import annotations

import ast

#: Module version.
REC_08_VERSION = "rec-tree-size.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.rec-tree-size.v1"


class RecError(Exception):
    """Fail-closed."""


#: Binary tree node: (value, left, right); None is empty.
SAMPLE = (1, (2, (4, None, None), (5, None, None)), (3, None, (6, None, None)))
def size(t) -> int:
    """Node count of tuple tree."""
    if t is None:
        return 0
    _, l, r = t
    return 1 + size(l) + size(r)

def test_size_empty():
    assert size(None) == 0


def test_size_single():
    assert size((9, None, None)) == 1


def test_size_sample():
    assert size(SAMPLE) == 6

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
    test_size_empty()
    test_size_single()
    test_size_sample()
    assert stdlib_only()
    print("rec-tree-size OK")


if __name__ == "__main__":
    main()
