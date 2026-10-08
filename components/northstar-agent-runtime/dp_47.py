"""dp-47: Longest valid parentheses.

Length of the longest well-formed parentheses substring. dp[i] is the longest valid substring ending at i.

Time complexity: O(n) time
Space complexity: O(n) space
"""

import ast
import sys

DP_47_VERSION = "dp-47.v1"


def longest_valid(s: str) -> int:
    """Return the length of the longest valid parentheses substring."""
    dp = [0] * len(s)
    best = 0
    for i in range(1, len(s)):
        if s[i] == ")":
            if s[i - 1] == "(":
                dp[i] = (dp[i - 2] if i >= 2 else 0) + 2
            elif i - dp[i - 1] - 1 >= 0 and s[i - dp[i - 1] - 1] == "(":
                dp[i] = dp[i - 1] + 2 + (dp[i - dp[i - 1] - 2]
                                         if i - dp[i - 1] - 2 >= 0 else 0)
            best = max(best, dp[i])
    return best


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
    assert longest_valid("(()") == 2
    assert longest_valid(")()())") == 4
    assert longest_valid("") == 0
    assert longest_valid("()(())") == 6
    assert longest_valid("(((") == 0
    assert longest_valid(")()())()()(") == 4
    assert stdlib_only()
    print("dp-47 OK")


if __name__ == "__main__":
    main()
