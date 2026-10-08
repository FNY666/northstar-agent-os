"""cc-31: Fibonacci denominations counting.

Count combinations when denominations are Fibonacci numbers.

Time complexity: O(amount * log_phi amount) time
Space complexity: O(amount)
"""

import ast
import sys

CC_31_VERSION = "cc-31.v1"


def fibonacci_denominations(limit: int) -> list:
    """Fibonacci numbers (1, 2, 3, 5, ...) not exceeding limit."""
    if limit < 0:
        raise ValueError("limit must be non-negative")
    out = []
    a, b = 1, 2
    while a <= limit:
        out.append(a)
        a, b = b, a + b
    return out


def count_ways_fib(amount: int) -> int:
    """Combinations of Fibonacci denominations summing to amount."""
    if amount < 0:
        raise ValueError("amount must be non-negative")
    denoms = fibonacci_denominations(amount)
    dp = [0] * (amount + 1)
    dp[0] = 1
    for d in denoms:
        for i in range(d, amount + 1):
            dp[i] += dp[i - d]
    return dp[amount]

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
    assert fibonacci_denominations(10) == [1, 2, 3, 5, 8]
    assert count_ways_fib(5) == 6
    assert count_ways_fib(0) == 1
    assert stdlib_only()
    print("cc-31 OK")


if __name__ == "__main__":
    main()
