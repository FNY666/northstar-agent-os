"""cc-38: Count ways with per-denomination caps.

Combination counting where each denomination has its own maximum usage count given as a dict.

Time complexity: O(amount * sum(caps)) time
Space complexity: O(amount)
"""

import ast
import sys

CC_38_VERSION = "cc-38.v1"


def count_ways_caps(amount: int, caps: dict) -> int:
    """Combinations summing to amount; caps maps denomination -> max count."""
    if amount < 0:
        raise ValueError("amount must be non-negative")
    if any(d <= 0 for d in caps) or any(c < 0 for c in caps.values()):
        raise ValueError("denominations positive, caps non-negative")
    dp = [0] * (amount + 1)
    dp[0] = 1
    for d, c in sorted(caps.items()):
        new = [0] * (amount + 1)
        for i in range(amount + 1):
            total = 0
            for k in range(c + 1):
                if k * d > i:
                    break
                total += dp[i - k * d]
            new[i] = total
        dp = new
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
    assert count_ways_caps(5, {1: 5, 2: 5, 5: 5}) == 4
    assert count_ways_caps(5, {1: 0, 2: 0, 5: 1}) == 1
    assert count_ways_caps(5, {5: 0}) == 0
    assert stdlib_only()
    print("cc-38 OK")


if __name__ == "__main__":
    main()
