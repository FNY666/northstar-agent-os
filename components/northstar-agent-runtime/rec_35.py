"""Climbing stairs: ways(n-1) + ways(n-2), memoised

Each step is 1 or 2 stairs; memoisation makes it O(n).

What this IS: a real memoised recursive stair-climb counter, fail-closed on negatives.
What this IS NOT: a substitute for iterative host code; the host picks the algorithm.
"""

from __future__ import annotations

import ast

#: Module version.
REC_35_VERSION = "rec-climb-stairs.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.rec-climb-stairs.v1"


class RecError(Exception):
    """Fail-closed."""


def climb(n: int, _memo=None) -> int:
    """Ways to climb n stairs (1 or 2 at a time)."""
    if n < 0:
        raise RecError("climb needs n >= 0")
    if _memo is None:
        _memo = {}
    if n in _memo:
        return _memo[n]
    if n <= 1:
        r = 1
    else:
        r = climb(n - 1, _memo) + climb(n - 2, _memo)
    _memo[n] = r
    return r

def test_climb_zero():
    assert climb(0) == 1


def test_climb_three():
    assert climb(3) == 3


def test_climb_five():
    assert climb(5) == 8


def test_climb_negative_raises():
    try:
        climb(-1)
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
    test_climb_zero()
    test_climb_three()
    test_climb_five()
    test_climb_negative_raises()
    assert stdlib_only()
    print("rec-climb-stairs OK")


if __name__ == "__main__":
    main()
