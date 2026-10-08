"""dp-21: Wildcard matching.

Match s against pattern p with '?' (any single char) and '*' (any sequence, including empty). 2-D DP.

Time complexity: O(m*n) time
Space complexity: O(m*n) space
"""

import ast
import sys

DP_21_VERSION = "dp-21.v1"


def wildcard_match(s: str, p: str) -> bool:
    """Return True when s matches wildcard pattern p ('?' and '*')."""
    m, n = len(s), len(p)
    dp = [[False] * (n + 1) for _ in range(m + 1)]
    dp[0][0] = True
    for j in range(1, n + 1):
        if p[j - 1] == "*":
            dp[0][j] = dp[0][j - 1]
    for i in range(1, m + 1):
        for j in range(1, n + 1):
            if p[j - 1] == "*":
                dp[i][j] = dp[i][j - 1] or dp[i - 1][j]
            elif p[j - 1] == "?" or p[j - 1] == s[i - 1]:
                dp[i][j] = dp[i - 1][j - 1]
    return dp[m][n]


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
    assert wildcard_match("aa", "a") is False
    assert wildcard_match("aa", "*") is True
    assert wildcard_match("cb", "?a") is False
    assert wildcard_match("adceb", "*a*b") is True
    assert wildcard_match("acdcb", "a*c?b") is False
    assert wildcard_match("", "*") is True
    assert wildcard_match("", "?") is False
    assert stdlib_only()
    print("dp-21 OK")


if __name__ == "__main__":
    main()
