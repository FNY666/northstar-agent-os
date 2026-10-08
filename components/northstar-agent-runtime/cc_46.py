"""cc-46: Count sequences with no adjacent equal coins.

Ordered coin sequences summing to amount where no two adjacent coins share a denomination.

Time complexity: O(amount * num_denominations^2) time
Space complexity: O(amount * num_denominations)
"""

import ast
import sys

CC_46_VERSION = "cc-46.v1"


def count_sequences_no_adjacent(amount: int, coins: list) -> int:
    """Ordered sequences summing to amount with no equal neighbours."""
    if amount < 0:
        raise ValueError("amount must be non-negative")
    denoms = sorted(set(coins))
    if any(d <= 0 for d in denoms):
        raise ValueError("denominations must be positive")
    if amount == 0:
        return 1
    dp = [{d: 0 for d in denoms} for _ in range(amount + 1)]
    for d in denoms:
        if d <= amount:
            dp[d][d] = 1
    for i in range(1, amount + 1):
        for d in denoms:
            if dp[i][d]:
                for e in denoms:
                    if e != d and i + e <= amount:
                        dp[i + e][e] += dp[i][d]
    return sum(dp[amount].values())

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
    assert count_sequences_no_adjacent(3, [1, 2]) == 2
    assert count_sequences_no_adjacent(2, [1, 2]) == 1
    assert count_sequences_no_adjacent(0, [1]) == 1
    assert stdlib_only()
    print("cc-46 OK")


if __name__ == "__main__":
    main()
