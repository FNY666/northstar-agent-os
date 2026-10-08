"""Memoized Tribonacci: memoization example.

Third-order recurrence T(n) = T(n-1) + T(n-2) + T(n-3) with T(0)=0, T(1)=T(2)=1. The cache turns an exponential recursion into O(n).

What this IS: a real O(n) memoized tribonacci, fail-closed on n < 0.
What this IS NOT: a closed-form or matrix implementation; the host picks the algorithm.
"""

from __future__ import annotations

import ast

#: Module version.
MEMO_02_VERSION = "memo-tribonacci.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.memo-tribonacci.v1"


class MemoError(Exception):
    """Fail-closed."""


def tribonacci(n: int, _cache: dict | None = None) -> int:
    """Memoized tribonacci. Fail-closed on n < 0."""
    if n < 0:
        raise MemoError("tribonacci needs n >= 0")
    cache: dict = _cache if _cache is not None else {}
    if n in cache:
        return cache[n]
    if n < 3:
        cache[n] = 0 if n == 0 else 1
    else:
        cache[n] = tribonacci(n - 1, cache) + tribonacci(n - 2, cache) + tribonacci(n - 3, cache)
    return cache[n]

def test_tribonacci_base():
    assert tribonacci(0) == 0
    assert tribonacci(1) == 1
    assert tribonacci(2) == 1


def test_tribonacci_10():
    assert tribonacci(10) == 149


def test_tribonacci_negative_raises():
    try:
        tribonacci(-2)
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
    test_tribonacci_base()
    test_tribonacci_10()
    test_tribonacci_negative_raises()
    assert stdlib_only()
    print("memo-02 OK: tribonacci")


if __name__ == "__main__":
    main()
