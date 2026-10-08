"""Memoized Coin Change (ways): memoization example.

Count combinations of coins summing to an amount: ways(amount, i) = ways(amount, i+1) + ways(amount - coins[i], i). The (amount, i) cache avoids re-solving subproblems.

What this IS: a real memoized coin-combination counter, fail-closed on negative amount.
What this IS NOT: a minimum-coins solver (see memo-50); the host picks the variant.
"""

from __future__ import annotations

import ast

#: Module version.
MEMO_05_VERSION = "memo-coin-change-ways.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.memo-coin-change-ways.v1"


class MemoError(Exception):
    """Fail-closed."""


def coin_ways(amount: int, coins: tuple, i: int = 0, _cache: dict | None = None) -> int:
    """Memoized coin-change way counter. Fail-closed on amount < 0."""
    if amount < 0:
        raise MemoError("coin_ways needs amount >= 0")
    cache: dict = _cache if _cache is not None else {}
    key = (amount, i)
    if key in cache:
        return cache[key]
    if amount == 0:
        cache[key] = 1
    elif i >= len(coins):
        cache[key] = 0
    else:
        take = coin_ways(amount - coins[i], coins, i, cache) if amount >= coins[i] else 0
        cache[key] = take + coin_ways(amount, coins, i + 1, cache)
    return cache[key]

def test_coin_ways_example():
    assert coin_ways(5, (1, 2, 5)) == 4


def test_coin_ways_impossible():
    assert coin_ways(3, (2,)) == 0


def test_coin_ways_zero():
    assert coin_ways(0, (1, 2)) == 1


def test_coin_ways_negative_raises():
    try:
        coin_ways(-1, (1,))
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
    test_coin_ways_example()
    test_coin_ways_impossible()
    test_coin_ways_zero()
    test_coin_ways_negative_raises()
    assert stdlib_only()
    print("memo-05 OK: coin-change-ways")


if __name__ == "__main__":
    main()
