"""cc-34: Subset-sum counting.

Count subsets of the given values summing exactly to target.

Time complexity: O(target * num_values) time
Space complexity: O(target)
"""

import ast
import sys

CC_34_VERSION = "cc-34.v1"


def subset_sum_count(values: list, target: int) -> int:
    """Number of subsets of values summing to target."""
    if target < 0:
        raise ValueError("target must be non-negative")
    if any(v <= 0 for v in values):
        raise ValueError("values must be positive")
    dp = [0] * (target + 1)
    dp[0] = 1
    for v in values:
        for i in range(target, v - 1, -1):
            dp[i] += dp[i - v]
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
    assert subset_sum_count([1, 2, 3], 3) == 2
    assert subset_sum_count([1, 2, 5], 8) == 0
    assert subset_sum_count([5], 0) == 1
    assert stdlib_only()
    print("cc-34 OK")


if __name__ == "__main__":
    main()
