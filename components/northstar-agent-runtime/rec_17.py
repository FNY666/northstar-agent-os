"""Combinations: take-or-skip the head

Either the head is in the k-set or it is not; C(n,k) results.

What this IS: a real recursive k-combination generator.
What this IS NOT: a substitute for iterative host code; the host picks the algorithm.
"""

from __future__ import annotations

import ast

#: Module version.
REC_17_VERSION = "rec-combinations.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.rec-combinations.v1"


class RecError(Exception):
    """Fail-closed."""


def combs(xs, k: int):
    """All k-combinations of xs as lists."""
    if k < 0:
        raise RecError("combs needs k >= 0")
    if k == 0:
        return [[]]
    if not xs:
        return []
    with_head = [[xs[0]] + c for c in combs(xs[1:], k - 1)]
    return with_head + combs(xs[1:], k)

def test_combs_basic():
    assert combs([1, 2, 3], 2) == [[1, 2], [1, 3], [2, 3]]


def test_combs_zero():
    assert combs([1, 2], 0) == [[]]


def test_combs_too_many():
    assert combs([1, 2], 5) == []


def test_combs_negative_raises():
    try:
        combs([1], -1)
    except RecError:
        return
    raise AssertionError("expected RecError")

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
    test_combs_basic()
    test_combs_zero()
    test_combs_too_many()
    test_combs_negative_raises()
    assert stdlib_only()
    print("rec-combinations OK")


if __name__ == "__main__":
    main()
