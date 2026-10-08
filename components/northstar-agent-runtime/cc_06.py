"""cc-06: Greedy change + canonical-system check.

Greedy coin change (largest denomination first) plus a verifier that checks whether greedy is optimal for every amount up to a bound, i.e. whether the system is canonical.

Time complexity: O(check_upto^2 * num_denominations) time for the check
Space complexity: O(check_upto)
"""

import ast
import sys

CC_06_VERSION = "cc-06.v1"


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
    return dp[amount] if dp[amount] != INF else -1


def greedy_min_coins(amount: int, coins: list):
    """Greedy change; returns (count, coins_used) or (-1, []) if it fails."""
    if amount < 0:
        raise ValueError("amount must be non-negative")
    denoms = sorted(set(coins), reverse=True)
    if any(d <= 0 for d in denoms):
        raise ValueError("denominations must be positive")
    used = []
    rem = amount
    for d in denoms:
        while rem >= d:
            rem -= d
            used.append(d)
    if rem != 0:
        return (-1, [])
    return (len(used), used)


def is_canonical(coins: list, check_upto: int = 200) -> bool:
    """True when greedy matches optimal for every amount in [0, check_upto]."""
    denoms = sorted(set(coins))
    if any(d <= 0 for d in denoms):
        raise ValueError("denominations must be positive")
    for a in range(check_upto + 1):
        g, _ = greedy_min_coins(a, denoms)
        if g != _min_coins_dp(a, denoms):
            return False
    return True

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
    assert greedy_min_coins(63, [25, 10, 5, 1]) == (6, [25, 25, 10, 1, 1, 1])
    assert greedy_min_coins(3, [2, 4]) == (-1, [])
    assert is_canonical([25, 10, 5, 1]) is True
    assert is_canonical([1, 3, 4]) is False
    assert stdlib_only()
    print("cc-06 OK")


if __name__ == "__main__":
    main()
