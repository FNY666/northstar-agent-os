"""Memoized Rod Cutting: memoization example.

Max revenue for a rod of length n: try every first cut. The length-keyed cache gives O(n^2) with a price list.

What this IS: a real memoized rod-cutting maximizer, fail-closed on n < 0.
What this IS NOT: a cut-reconstruction routine; the host picks the output shape.
"""

from __future__ import annotations

import ast

#: Module version.
MEMO_13_VERSION = "memo-rod-cutting.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.memo-rod-cutting.v1"


class MemoError(Exception):
    """Fail-closed."""


def rod_cut(prices: tuple, n: int, _cache: dict | None = None) -> int:
    """Memoized rod-cutting max revenue. Fail-closed on n < 0."""
    if n < 0:
        raise MemoError("rod_cut needs n >= 0")
    cache: dict = _cache if _cache is not None else {}
    if n in cache:
        return cache[n]
    if n == 0:
        cache[n] = 0
    else:
        cache[n] = max(prices[i] + rod_cut(prices, n - i - 1, cache) for i in range(min(n, len(prices))))
    return cache[n]

def test_rod_cut_example():
    assert rod_cut((1, 5, 8, 9, 10, 17, 17, 20), 8) == 22


def test_rod_cut_zero():
    assert rod_cut((1, 5), 0) == 0


def test_rod_cut_negative_raises():
    try:
        rod_cut((1,), -1)
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
    test_rod_cut_example()
    test_rod_cut_zero()
    test_rod_cut_negative_raises()
    assert stdlib_only()
    print("memo-13 OK: rod-cutting")


if __name__ == "__main__":
    main()
