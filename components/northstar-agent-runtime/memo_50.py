"""Memoized Coin Change (min coins): memoization example.

Fewest coins summing to an amount: 1 + min over usable coins, -1 when impossible. The amount cache gives O(amount * |coins|).

What this IS: a real memoized min-coin solver returning -1 when impossible, fail-closed on negative amount.
What this IS NOT: a way counter (see memo-05); the host picks the variant.
"""

from __future__ import annotations

import ast

#: Module version.
MEMO_50_VERSION = "memo-coin-change-min.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.memo-coin-change-min.v1"


class MemoError(Exception):
    """Fail-closed."""


def min_coins(coins: tuple, amount: int, _cache: dict | None = None) -> int:
    """Memoized fewest-coin counter; -1 when impossible. Fail-closed on amount < 0."""
    if amount < 0:
        raise MemoError("min_coins needs amount >= 0")
    cache: dict = _cache if _cache is not None else {}
    if amount in cache:
        return cache[amount]
    if amount == 0:
        cache[amount] = 0
    else:
        best = float("inf")
        for c in coins:
            if c <= amount:
                sub = min_coins(coins, amount - c, cache)
                if sub != -1:
                    best = min(best, 1 + sub)
        cache[amount] = -1 if best == float("inf") else best
    return cache[amount]

def test_min_coins_example():
    assert min_coins((1, 2, 5), 11) == 3


def test_min_coins_impossible():
    assert min_coins((2,), 3) == -1


def test_min_coins_negative_raises():
    try:
        min_coins((1,), -1)
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
    test_min_coins_example()
    test_min_coins_impossible()
    test_min_coins_negative_raises()
    assert stdlib_only()
    print("memo-50 OK: coin-change-min")


if __name__ == "__main__":
    main()
