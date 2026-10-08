"""Catalan numbers: sum of C(i)*C(n-1-i), memoised

Counts bracketings, Dyck paths, and friends; O(n^2) with memo.

What this IS: a real memoised recursive Catalan, fail-closed on negatives.
What this IS NOT: a substitute for iterative host code; the host picks the algorithm.
"""

from __future__ import annotations

import ast

#: Module version.
REC_39_VERSION = "rec-catalan.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.rec-catalan.v1"


class RecError(Exception):
    """Fail-closed."""


def catalan(n: int, _memo=None) -> int:
    """n-th Catalan number. Fail-closed on negatives."""
    if n < 0:
        raise RecError("catalan needs n >= 0")
    if _memo is None:
        _memo = {}
    if n in _memo:
        return _memo[n]
    if n <= 1:
        r = 1
    else:
        r = sum(catalan(i, _memo) * catalan(n - 1 - i, _memo) for i in range(n))
    _memo[n] = r
    return r

def test_catalan_zero():
    assert catalan(0) == 1


def test_catalan_four():
    assert catalan(4) == 14


def test_catalan_five():
    assert catalan(5) == 42


def test_catalan_negative_raises():
    try:
        catalan(-1)
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
    test_catalan_zero()
    test_catalan_four()
    test_catalan_five()
    test_catalan_negative_raises()
    assert stdlib_only()
    print("rec-catalan OK")


if __name__ == "__main__":
    main()
