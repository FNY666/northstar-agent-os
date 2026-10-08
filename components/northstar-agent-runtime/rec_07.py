"""Tree height: 1 + max(child heights)

Empty tree has height 0; a single node has height 1.

What this IS: a real recursive tree height.
What this IS NOT: a substitute for iterative host code; the host picks the algorithm.
"""

from __future__ import annotations

import ast

#: Module version.
REC_07_VERSION = "rec-tree-height.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.rec-tree-height.v1"


class RecError(Exception):
    """Fail-closed."""


#: Binary tree node: (value, left, right); None is empty.
SAMPLE = (1, (2, (4, None, None), (5, None, None)), (3, None, (6, None, None)))
def height(t) -> int:
    """Height of tuple tree."""
    if t is None:
        return 0
    _, l, r = t
    return 1 + max(height(l), height(r))

def test_height_empty():
    assert height(None) == 0


def test_height_single():
    assert height((9, None, None)) == 1


def test_height_sample():
    assert height(SAMPLE) == 3

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
    test_height_empty()
    test_height_single()
    test_height_sample()
    assert stdlib_only()
    print("rec-tree-height OK")


if __name__ == "__main__":
    main()
