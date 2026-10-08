"""Fibonacci: fib(n) with memoised recursion

Naive recursion is exponential; the memo dict makes it O(n) time and O(n) space.

What this IS: a real memoised recursive Fibonacci, fail-closed on negatives.
What this IS NOT: a substitute for iterative host code; the host picks the algorithm.
"""

from __future__ import annotations

import ast

#: Module version.
REC_02_VERSION = "rec-fibonacci.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.rec-fibonacci.v1"


class RecError(Exception):
    """Fail-closed."""


def fib(n: int, _memo=None) -> int:
    """fib(n). Fail-closed on negatives."""
    if n < 0:
        raise RecError("fib needs n >= 0")
    if _memo is None:
        _memo = {}
    if n in _memo:
        return _memo[n]
    if n <= 1:
        r = n
    else:
        r = fib(n - 1, _memo) + fib(n - 2, _memo)
    _memo[n] = r
    return r

def test_fib_zero():
    assert fib(0) == 0


def test_fib_one():
    assert fib(1) == 1


def test_fib_ten():
    assert fib(10) == 55


def test_fib_twenty():
    assert fib(20) == 6765


def test_fib_negative_raises():
    try:
        fib(-2)
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
    test_fib_zero()
    test_fib_one()
    test_fib_ten()
    test_fib_twenty()
    test_fib_negative_raises()
    assert stdlib_only()
    print("rec-fibonacci OK")


if __name__ == "__main__":
    main()
