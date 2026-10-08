"""dp-50: Number of dice rolls with target sum.

Ways to roll n k-sided dice summing to target (mod 1e9+7). dp[t] rolls forward one die at a time.

Time complexity: O(n * target * k) time
Space complexity: O(target) space
"""

import ast
import sys

DP_50_VERSION = "dp-50.v1"


def dice_rolls(n: int, k: int, target: int) -> int:
    """Return the number of ways n k-sided dice sum to target (mod 1e9+7)."""
    if n <= 0 or k <= 0 or target < 0:
        raise ValueError("n, k must be positive and target non-negative")
    MOD = 10 ** 9 + 7
    dp = [0] * (target + 1)
    dp[0] = 1
    for _ in range(n):
        nxt = [0] * (target + 1)
        for t in range(1, target + 1):
            total = 0
            for f in range(1, min(k, t) + 1):
                total += dp[t - f]
            nxt[t] = total % MOD
        dp = nxt
    return dp[target]


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
    assert dice_rolls(1, 6, 3) == 1
    assert dice_rolls(2, 6, 7) == 6
    assert dice_rolls(2, 5, 10) == 1
    assert dice_rolls(2, 6, 1) == 0
    assert dice_rolls(1, 6, 6) == 1
    assert dice_rolls(3, 6, 3) == 1
    try:
        dice_rolls(0, 6, 3)
        raise AssertionError("expected ValueError")
    except ValueError:
        pass
    assert stdlib_only()
    print("dp-50 OK")


if __name__ == "__main__":
    main()
