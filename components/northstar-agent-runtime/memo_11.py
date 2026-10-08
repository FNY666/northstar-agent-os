"""Memoized Catalan Numbers: memoization example.

Catalan recurrence C(n) = sum(C(i) * C(n-1-i)). The cache turns the exponential recursion into O(n^2).

What this IS: a real O(n^2) memoized Catalan number, fail-closed on n < 0.
What this IS NOT: a closed-form binomial implementation; the host picks the algorithm.
"""

from __future__ import annotations

import ast

#: Module version.
MEMO_11_VERSION = "memo-catalan.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.memo-catalan.v1"


class MemoError(Exception):
    """Fail-closed."""


def catalan(n: int, _cache: dict | None = None) -> int:
    """Memoized Catalan number. Fail-closed on n < 0."""
    if n < 0:
        raise MemoError("catalan needs n >= 0")
    cache: dict = _cache if _cache is not None else {}
    if n in cache:
        return cache[n]
    if n <= 1:
        cache[n] = 1
    else:
        cache[n] = sum(catalan(i, cache) * catalan(n - 1 - i, cache) for i in range(n))
    return cache[n]

def test_catalan_base():
    assert catalan(0) == 1
    assert catalan(1) == 1


def test_catalan_5():
    assert catalan(5) == 42


def test_catalan_negative_raises():
    try:
        catalan(-1)
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
    test_catalan_base()
    test_catalan_5()
    test_catalan_negative_raises()
    assert stdlib_only()
    print("memo-11 OK: catalan")


if __name__ == "__main__":
    main()
