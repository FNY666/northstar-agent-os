"""Memoized Ugly Number: memoization example.

n-th ugly number (prime factors only 2, 3, 5): scan upward with a memoized ugliness test sharing factor-stripping work.

What this IS: a real memoized n-th ugly number, fail-closed on n < 1.
What this IS NOT: a three-pointer O(n) generator; the host picks the algorithm.
"""

from __future__ import annotations

import ast

#: Module version.
MEMO_29_VERSION = "memo-ugly-number.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.memo-ugly-number.v1"


class MemoError(Exception):
    """Fail-closed."""


def nth_ugly(n: int, _cache: dict | None = None) -> int:
    """Memoized n-th ugly number. Fail-closed on n < 1."""
    if n < 1:
        raise MemoError("nth_ugly needs n >= 1")
    cache: dict = _cache if _cache is not None else {}

    def is_ugly(x: int) -> bool:
        if x in cache:
            return cache[x]
        if x <= 0:
            cache[x] = False
        elif x == 1:
            cache[x] = True
        else:
            y = x
            for p in (2, 3, 5):
                while y % p == 0:
                    y //= p
            cache[x] = y == 1
        return cache[x]

    count = 0
    x = 1
    while True:
        if is_ugly(x):
            count += 1
            if count == n:
                return x
        x += 1

def test_nth_ugly_10():
    assert nth_ugly(10) == 12


def test_nth_ugly_1():
    assert nth_ugly(1) == 1


def test_nth_ugly_zero_raises():
    try:
        nth_ugly(0)
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
    test_nth_ugly_10()
    test_nth_ugly_1()
    test_nth_ugly_zero_raises()
    assert stdlib_only()
    print("memo-29 OK: ugly-number")


if __name__ == "__main__":
    main()
