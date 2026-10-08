"""Memoized Fibonacci: memoization example.

Classic linear recurrence F(n) = F(n-1) + F(n-2). Naive recursion is exponential; threading an explicit cache dict through the recursion makes it linear.

What this IS: a real O(n) memoized Fibonacci with an explicit cache, fail-closed on n < 0.
What this IS NOT: a matrix-exponentiation fast doubling implementation; the host picks the algorithm.
"""

from __future__ import annotations

import ast

#: Module version.
MEMO_01_VERSION = "memo-fibonacci.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.memo-fibonacci.v1"


class MemoError(Exception):
    """Fail-closed."""


def fib(n: int, _cache: dict | None = None) -> int:
    """Memoized Fibonacci. Fail-closed on n < 0."""
    if n < 0:
        raise MemoError("fib needs n >= 0")
    cache: dict = _cache if _cache is not None else {}
    if n in cache:
        return cache[n]
    cache[n] = n if n < 2 else fib(n - 1, cache) + fib(n - 2, cache)
    return cache[n]

def test_fib_base():
    assert fib(0) == 0
    assert fib(1) == 1


def test_fib_10():
    assert fib(10) == 55


def test_fib_20():
    assert fib(20) == 6765


def test_fib_negative_raises():
    try:
        fib(-1)
    except MemoError:
        return
    raise AssertionError("expected MemoError")

def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    """Self-check."""
    test_fib_base()
    test_fib_10()
    test_fib_20()
    test_fib_negative_raises()
    assert stdlib_only()
    print("memo-01 OK: fibonacci")


if __name__ == "__main__":
    main()
