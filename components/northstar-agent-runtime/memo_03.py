"""Memoized Climbing Stairs: memoization example.

Count ways to climb n stairs taking 1 or 2 steps: ways(n) = ways(n-1) + ways(n-2). The cache collapses the exponential recursion to linear.

What this IS: a real O(n) memoized stair-count, fail-closed on n < 0.
What this IS NOT: a combinatorial closed form; the host picks the algorithm.
"""

from __future__ import annotations

import ast

#: Module version.
MEMO_03_VERSION = "memo-climb-stairs.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.memo-climb-stairs.v1"


class MemoError(Exception):
    """Fail-closed."""


def climb(n: int, _cache: dict | None = None) -> int:
    """Memoized stair-climb count. Fail-closed on n < 0."""
    if n < 0:
        raise MemoError("climb needs n >= 0")
    cache: dict = _cache if _cache is not None else {}
    if n in cache:
        return cache[n]
    cache[n] = 1 if n <= 1 else climb(n - 1, cache) + climb(n - 2, cache)
    return cache[n]

def test_climb_base():
    assert climb(0) == 1
    assert climb(1) == 1
    assert climb(2) == 2


def test_climb_10():
    assert climb(10) == 89


def test_climb_negative_raises():
    try:
        climb(-1)
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
    test_climb_base()
    test_climb_10()
    test_climb_negative_raises()
    assert stdlib_only()
    print("memo-03 OK: climb-stairs")


if __name__ == "__main__":
    main()
