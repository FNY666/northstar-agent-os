"""Memoized Perfect Squares: memoization example.

Fewest squares summing to n: 1 + min over square remainders. The cache gives O(n sqrt n).

What this IS: a real memoized least-squares counter, fail-closed on n < 0.
What this IS NOT: a square-decomposition builder; the host picks the output shape.
"""

from __future__ import annotations

import ast

#: Module version.
MEMO_26_VERSION = "memo-perfect-squares.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.memo-perfect-squares.v1"


class MemoError(Exception):
    """Fail-closed."""


def num_squares(n: int, _cache: dict | None = None) -> int:
    """Memoized fewest-squares counter. Fail-closed on n < 0."""
    if n < 0:
        raise MemoError("num_squares needs n >= 0")
    cache: dict = _cache if _cache is not None else {}
    if n in cache:
        return cache[n]
    if n == 0:
        cache[n] = 0
    else:
        cache[n] = 1 + min(num_squares(n - i * i, cache) for i in range(1, int(n ** 0.5) + 1))
    return cache[n]

def test_num_squares_12():
    assert num_squares(12) == 3


def test_num_squares_square():
    assert num_squares(16) == 1


def test_num_squares_negative_raises():
    try:
        num_squares(-4)
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
    test_num_squares_12()
    test_num_squares_square()
    test_num_squares_negative_raises()
    assert stdlib_only()
    print("memo-26 OK: perfect-squares")


if __name__ == "__main__":
    main()
