"""cc-22: Arithmetic-progression denominations.

Denominations generated as start, start+step, ...; then classic minimum-coin change on the generated set.

Time complexity: O(amount * count) time
Space complexity: O(amount)
"""

import ast
import sys

CC_22_VERSION = "cc-22.v1"


def arithmetic_denominations(start: int, step: int, count: int) -> list:
    """Generate [start, start+step, ..., start+step*(count-1)]."""
    if count < 0:
        raise ValueError("count must be non-negative")
    if step <= 0:
        raise ValueError("step must be positive")
    return [start + step * i for i in range(count)]


def min_coins_arith(amount: int, start: int, step: int, count: int) -> int:
    """Min coins using arithmetic-progression denominations."""
    denoms = [d for d in arithmetic_denominations(start, step, count) if d > 0]
    if amount < 0:
        raise ValueError("amount must be non-negative")
    if amount == 0:
        return 0
    if not denoms:
        return -1
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
    assert arithmetic_denominations(1, 2, 4) == [1, 3, 5, 7]
    assert min_coins_arith(11, 1, 2, 4) == 3
    assert min_coins_arith(3, 2, 2, 2) == -1
    assert stdlib_only()
    print("cc-22 OK")


if __name__ == "__main__":
    main()
