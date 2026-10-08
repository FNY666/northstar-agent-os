"""cc-18: Minimum coins (prime denominations only).

Filter the denominations down to primes, then run classic minimum-coin change on the primes.

Time complexity: O(amount * num_primes + max_denom^1.5) time
Space complexity: O(amount)
"""

import ast
import sys

CC_18_VERSION = "cc-18.v1"


def _is_prime(n: int) -> bool:
    if n < 2:
        return False
    if n % 2 == 0:
        return n == 2
    r = 3
    while r * r <= n:
        if n % r == 0:
            return False
        r += 2
    return True


def min_coins_prime_denoms(amount: int, coins: list) -> int:
    """Fewest coins using only prime denominations; -1 if impossible."""
    if amount < 0:
        raise ValueError("amount must be non-negative")
    if any(d <= 0 for d in coins):
        raise ValueError("denominations must be positive")
    primes = sorted(d for d in set(coins) if _is_prime(d))
    if amount == 0:
        return 0
    if not primes:
        return -1
    INF = amount + 1
    dp = [INF] * (amount + 1)
    dp[0] = 0
    for i in range(1, amount + 1):
        best = INF
        for d in primes:
            if d > i:
                break
            if dp[i - d] + 1 < best:
                best = dp[i - d] + 1
        dp[i] = best
    return dp[amount] if dp[amount] != INF else -1

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
    assert min_coins_prime_denoms(10, [1, 2, 5, 10]) == 2
    assert min_coins_prime_denoms(11, [1, 2, 5, 10]) == 4
    assert min_coins_prime_denoms(7, [2, 3, 7]) == 1
    assert stdlib_only()
    print("cc-18 OK")


if __name__ == "__main__":
    main()
