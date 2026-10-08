"""cc-29: Powers-of-two denominations (greedy optimal).

Denominations are powers of two, a canonical system where greedy is provably optimal; the module cross-checks greedy against DP.

Time complexity: O(log amount) time for greedy
Space complexity: O(1)
"""

import ast
import sys

CC_29_VERSION = "cc-29.v1"


def powers_of_two(limit: int) -> list:
    """Powers of two not exceeding limit."""
    if limit < 0:
        raise ValueError("limit must be non-negative")
    out = []
    p = 1
    while p <= limit:
        out.append(p)
        p *= 2
    return out


def _min_coins_dp(amount, denoms):
    INF = amount + 1
    dp = [INF] * (amount + 1)
    dp[0] = 0
    for i in range(1, amount + 1):
        best = INF
        for d in denoms:
            if d > i:
                break
            if dp[i - d] + 1 < best:
                best = dp[i - d] + 1
        dp[i] = best
    return dp[amount]


def min_coins_pow2(amount: int) -> int:
    """Fewest powers of two summing to amount (greedy)."""
    if amount < 0:
        raise ValueError("amount must be non-negative")
    denoms = powers_of_two(amount)
    count, rem = 0, amount
    for d in reversed(denoms):
        count += rem // d
        rem %= d
    return count

def stdlib_only() -> bool:
    """Parse this file with ``ast`` and assert every import is a used stdlib module."""
    with open(__file__, encoding="utf-8") as f:
        source = f.read()
    tree = ast.parse(source)
    imported = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imported[alias.asname or alias.name.split(".")[0]] = alias.name.split(".")[0]
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                imported[alias.asname or alias.name] = (node.module or "").split(".")[0]
    used = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            used.add(node.id)
    for alias, top in imported.items():
        assert top in sys.stdlib_module_names, "non-stdlib import: %s" % top
        assert alias in used, "imported but unused: %s" % alias
    return True


def main() -> None:
    assert powers_of_two(10) == [1, 2, 4, 8]
    assert min_coins_pow2(11) == 3
    assert min_coins_pow2(0) == 0
    denoms = powers_of_two(63)
    for a in range(64):
        assert min_coins_pow2(a) == _min_coins_dp(a, denoms)
    assert stdlib_only()
    print("cc-29 OK")


if __name__ == "__main__":
    main()
