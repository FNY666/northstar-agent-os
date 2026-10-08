"""Internal-node count: non-leaf nodes

A node with at least one child contributes 1.

What this IS: a real recursive internal-node counter.
What this IS NOT: a substitute for iterative host code; the host picks the algorithm.
"""

from __future__ import annotations

import ast

#: Module version.
REC_46_VERSION = "rec-internal-nodes.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.rec-internal-nodes.v1"


class RecError(Exception):
    """Fail-closed."""


#: Binary tree node: (value, left, right); None is empty.
SAMPLE = (1, (2, (4, None, None), (5, None, None)), (3, None, (6, None, None)))
def count_internal(t) -> int:
    """Internal (non-leaf) node count."""
    if t is None:
        return 0
    _, l, r = t
    if l is None and r is None:
        return 0
    return 1 + count_internal(l) + count_internal(r)

def test_internal_empty():
    assert count_internal(None) == 0


def test_internal_single():
    assert count_internal((9, None, None)) == 0


def test_internal_sample():
    assert count_internal(SAMPLE) == 3

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
    test_internal_empty()
    test_internal_single()
    test_internal_sample()
    assert stdlib_only()
    print("rec-internal-nodes OK")


if __name__ == "__main__":
    main()
