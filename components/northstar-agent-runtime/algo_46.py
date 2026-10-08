"""Coin change (minimum coins) via dynamic programming.

Unbounded knapsack recurrence over amounts:

    dp[x] = min(dp[x], dp[x - c] + 1)   for each coin c <= x

dp[0] = 0, others start at +infinity. Time O(amount * len(coins)),
space O(amount). Returns -1 when ``amount`` cannot be formed.
Coins must be positive ints; ``ValueError`` is raised otherwise.
"""

import ast
import sys
from pathlib import Path
from typing import List, Sequence

ALGO_46_VERSION = "algo-46.v1"

STDLIB_USED = frozenset({"ast", "pathlib", "sys", "typing"})


def stdlib_only() -> bool:
    """Parse this file with ``ast`` and assert every imported top-level module
    is one this module actually uses from the standard library."""
    tree = ast.parse(Path(__file__).read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imported.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imported.add(node.module.split(".")[0])
    stdlib_names = set(sys.stdlib_module_names)
    for name in sorted(imported):
        assert name in stdlib_names, "non-stdlib import: %s" % name
        assert name in STDLIB_USED, "imported but unused module: %s" % name
    assert set(STDLIB_USED) == imported, (
        "import drift: declared %s vs found %s"
        % (sorted(STDLIB_USED), sorted(imported))
    )
    return True


def coin_change(coins: Sequence[int], amount: int) -> int:
    """Return the fewest coins making ``amount``, or -1 if impossible."""
    if amount < 0:
        raise ValueError("amount must be non-negative, got %r" % (amount,))
    coins = list(coins)
    for c in coins:
        if c <= 0:
            raise ValueError("coins must be positive ints, got %r" % (c,))
    inf = amount + 1
    dp: List[int] = [inf] * (amount + 1)
    dp[0] = 0
    for c in coins:
        for x in range(c, amount + 1):
            cand = dp[x - c] + 1
            if cand < dp[x]:
                dp[x] = cand
    return -1 if dp[amount] == inf else dp[amount]


def main() -> None:
    assert coin_change([1, 2, 5], 11) == 3
    assert coin_change([2], 3) == -1
    assert coin_change([1], 0) == 0
    assert coin_change([5], 5) == 1
    assert coin_change([], 0) == 0
    assert coin_change([], 7) == -1
    assert coin_change([186, 419, 83, 408], 6249) == 20
    try:
        coin_change([1, -2], 5)
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for non-positive coin")
    assert stdlib_only()
    print("algo-46 OK")


if __name__ == "__main__":
    main()
