"""Root-to-leaf path sum: target minus node value

A leaf matches when its value equals the remaining target.

What this IS: a real recursive path-sum existence check.
What this IS NOT: a substitute for iterative host code; the host picks the algorithm.
"""

from __future__ import annotations

import ast

#: Module version.
REC_29_VERSION = "rec-path-sum.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.rec-path-sum.v1"


class RecError(Exception):
    """Fail-closed."""


#: Binary tree node: (value, left, right); None is empty.
SAMPLE = (1, (2, (4, None, None), (5, None, None)), (3, None, (6, None, None)))
def has_path_sum(t, target) -> bool:
    """True when a root-to-leaf path sums to target."""
    if t is None:
        return False
    v, l, r = t
    if l is None and r is None:
        return v == target
    return has_path_sum(l, target - v) or has_path_sum(r, target - v)

def test_path_sum_true():
    assert has_path_sum(SAMPLE, 1 + 2 + 4) is True


def test_path_sum_false():
    assert has_path_sum(SAMPLE, 999) is False


def test_path_sum_empty():
    assert has_path_sum(None, 0) is False


def test_path_sum_single():
    assert has_path_sum((5, None, None), 5) is True

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
    test_path_sum_true()
    test_path_sum_false()
    test_path_sum_empty()
    test_path_sum_single()
    assert stdlib_only()
    print("rec-path-sum OK")


if __name__ == "__main__":
    main()
