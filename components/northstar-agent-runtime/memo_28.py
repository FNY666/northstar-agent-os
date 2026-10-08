"""Memoized Counting Bits: memoization example.

Popcount for 0..n via bits(k) = bits(k >> 1) + (k & 1). The cache shares subproblems across the whole range.

What this IS: a real memoized popcount table builder, fail-closed on n < 0.
What this IS NOT: a vectorized popcount; the host picks the algorithm.
"""

from __future__ import annotations

import ast

#: Module version.
MEMO_28_VERSION = "memo-counting-bits.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.memo-counting-bits.v1"


class MemoError(Exception):
    """Fail-closed."""


def count_bits(n: int, _cache: dict | None = None) -> list:
    """Memoized popcount table for 0..n. Fail-closed on n < 0."""
    if n < 0:
        raise MemoError("count_bits needs n >= 0")
    cache: dict = _cache if _cache is not None else {}

    def bits(k: int) -> int:
        if k in cache:
            return cache[k]
        cache[k] = 0 if k == 0 else bits(k >> 1) + (k & 1)
        return cache[k]

    return [bits(k) for k in range(n + 1)]

def test_count_bits_5():
    assert count_bits(5) == [0, 1, 1, 2, 1, 2]


def test_count_bits_0():
    assert count_bits(0) == [0]


def test_count_bits_negative_raises():
    try:
        count_bits(-1)
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
    test_count_bits_5()
    test_count_bits_0()
    test_count_bits_negative_raises()
    assert stdlib_only()
    print("memo-28 OK: counting-bits")


if __name__ == "__main__":
    main()
