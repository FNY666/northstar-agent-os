"""dp-45: Integer break.

Break n into a sum of >= 2 positive integers maximizing the product. dp[i] considers every first cut j.

Time complexity: O(n^2) time
Space complexity: O(n) space
"""

import ast
import sys

DP_45_VERSION = "dp-45.v1"


def integer_break(n: int) -> int:
    """Return the maximum product from breaking n into >= 2 integers."""
    if n < 2:
        raise ValueError("n must be at least 2")
    dp = [0] * (n + 1)
    for i in range(2, n + 1):
        for j in range(1, i):
            dp[i] = max(dp[i], max(j, dp[j]) * max(i - j, dp[i - j]))
    return dp[n]


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
    assert integer_break(2) == 1
    assert integer_break(3) == 2
    assert integer_break(10) == 36
    assert integer_break(4) == 4
    assert integer_break(8) == 18
    try:
        integer_break(1)
        raise AssertionError("expected ValueError")
    except ValueError:
        pass
    assert stdlib_only()
    print("dp-45 OK")


if __name__ == "__main__":
    main()
