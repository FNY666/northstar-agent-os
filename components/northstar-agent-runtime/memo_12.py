"""Memoized Integer Partitions: memoization example.

Partition count p(n, max) = p(n, max-1) + p(n-max, max). The (n, max) cache gives O(n^2) states.

What this IS: a real memoized integer-partition counter, fail-closed on n < 0.
What this IS NOT: a pentagonal-theorem implementation; the host picks the algorithm.
"""

from __future__ import annotations

import ast

#: Module version.
MEMO_12_VERSION = "memo-integer-partitions.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.memo-integer-partitions.v1"


class MemoError(Exception):
    """Fail-closed."""


def partitions(n: int, max_part: int | None = None, _cache: dict | None = None) -> int:
    """Memoized integer partition count. Fail-closed on n < 0."""
    if n < 0:
        raise MemoError("partitions needs n >= 0")
    if max_part is None:
        max_part = n
    cache: dict = _cache if _cache is not None else {}
    key = (n, max_part)
    if key in cache:
        return cache[key]
    if n == 0:
        cache[key] = 1
    elif max_part == 0:
        cache[key] = 0
    else:
        skip = partitions(n, max_part - 1, cache)
        take = partitions(n - max_part, max_part, cache) if max_part <= n else 0
        cache[key] = skip + take
    return cache[key]

def test_partitions_5():
    assert partitions(5) == 7


def test_partitions_zero():
    assert partitions(0) == 1


def test_partitions_negative_raises():
    try:
        partitions(-3)
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
    test_partitions_5()
    test_partitions_zero()
    test_partitions_negative_raises()
    assert stdlib_only()
    print("memo-12 OK: integer-partitions")


if __name__ == "__main__":
    main()
