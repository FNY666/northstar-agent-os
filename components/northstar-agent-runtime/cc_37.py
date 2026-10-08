"""cc-37: Lexicographically smallest optimal change.

Among all minimum-coin solutions, return the lexicographically smallest coin list (ascending).

Time complexity: O(amount * num_denominations) time
Space complexity: O(amount)
"""

import ast
import sys

CC_37_VERSION = "cc-37.v1"


def min_coins_lex_smallest(amount: int, coins: list):
    """(min_count, lex-smallest coin list) or (-1, []) when impossible."""
    if amount < 0:
        raise ValueError("amount must be non-negative")
    denoms = sorted(set(coins))
    if any(d <= 0 for d in denoms):
        raise ValueError("denominations must be positive")
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
    if dp[amount] == INF:
        return (-1, [])
    out = []
    cur = amount
    for d in denoms:
        while cur >= d and dp[cur] == dp[cur - d] + 1:
            out.append(d)
            cur -= d
    return (dp[amount], out)

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
    assert min_coins_lex_smallest(6, [1, 3, 4]) == (2, [3, 3])
    assert min_coins_lex_smallest(11, [1, 2, 5]) == (3, [1, 5, 5])
    assert min_coins_lex_smallest(3, [2]) == (-1, [])
    assert stdlib_only()
    print("cc-37 OK")


if __name__ == "__main__":
    main()
