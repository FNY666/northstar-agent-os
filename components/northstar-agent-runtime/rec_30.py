"""Tree diameter: max path through each node

Returns (height, diameter); the diameter is the longest node-to-node path.

What this IS: a real single-pass recursive diameter.
What this IS NOT: a substitute for iterative host code; the host picks the algorithm.
"""

from __future__ import annotations

import ast

#: Module version.
REC_30_VERSION = "rec-tree-diameter.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.rec-tree-diameter.v1"


class RecError(Exception):
    """Fail-closed."""


#: Binary tree node: (value, left, right); None is empty.
SAMPLE = (1, (2, (4, None, None), (5, None, None)), (3, None, (6, None, None)))
def diameter(t):
    """(height, diameter) of tuple tree."""
    if t is None:
        return (0, 0)
    _, l, r = t
    hl, dl = diameter(l)
    hr, dr = diameter(r)
    return (1 + max(hl, hr), max(dl, dr, hl + hr + 1))

def test_diameter_empty():
    assert diameter(None) == (0, 0)


def test_diameter_single():
    assert diameter((9, None, None)) == (1, 1)


def test_diameter_sample():
    assert diameter(SAMPLE) == (3, 5)

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
    test_diameter_empty()
    test_diameter_single()
    test_diameter_sample()
    assert stdlib_only()
    print("rec-tree-diameter OK")


if __name__ == "__main__":
    main()
