"""Coin-change ways: use-or-skip each coin, memoised

Counts combinations (order of coins ignored) via index-based recursion.

What this IS: a real memoised recursive coin-change counter, fail-closed on negatives.
What this IS NOT: a substitute for iterative host code; the host picks the algorithm.
"""

from __future__ import annotations

import ast

#: Module version.
REC_36_VERSION = "rec-coin-ways.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.rec-coin-ways.v1"


class RecError(Exception):
    """Fail-closed."""


def coin_ways(amount: int, coins, i=0, _memo=None) -> int:
    """Ways to make amount with coins[i:]. Fail-closed on negative top-level amount."""
    if amount < 0:
        raise RecError("coin_ways needs amount >= 0")
    if _memo is None:
        _memo = {}

    def rec(amt, idx) -> int:
        if amt == 0:
            return 1
        if amt < 0 or idx >= len(coins):
            return 0
        key = (amt, idx)
        if key in _memo:
            return _memo[key]
        r = rec(amt - coins[idx], idx) + rec(amt, idx + 1)
        _memo[key] = r
        return r

    return rec(amount, i)

def test_coin_ways_basic():
    assert coin_ways(5, (1, 2, 5)) == 4


def test_coin_ways_zero():
    assert coin_ways(0, (1, 2)) == 1


def test_coin_ways_impossible():
    assert coin_ways(3, (2,)) == 0


def test_coin_ways_negative_raises():
    try:
        coin_ways(-1, (1,))
    except RecError:
        return
    raise AssertionError("expected RecError")

def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib"}
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                if a.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(n, ast.ImportFrom):
            if n.module and n.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    test_coin_ways_basic()
    test_coin_ways_zero()
    test_coin_ways_impossible()
    test_coin_ways_negative_raises()
    assert stdlib_only()
    print("rec-coin-ways OK")


if __name__ == "__main__":
    main()
