"""dp-39: Interleaving string.

Decide whether s3 is an interleave of s1 and s2 preserving each string's internal order. One rolling row.

Time complexity: O(m*n) time
Space complexity: O(n) space
"""

import ast
import sys

DP_39_VERSION = "dp-39.v1"


def is_interleave(s1: str, s2: str, s3: str) -> bool:
    """Return True when s3 interleaves s1 and s2."""
    m, n, k = len(s1), len(s2), len(s3)
    if m + n != k:
        return False
    dp = [False] * (n + 1)
    dp[0] = True
    for j in range(1, n + 1):
        dp[j] = dp[j - 1] and s2[j - 1] == s3[j - 1]
    for i in range(1, m + 1):
        dp[0] = dp[0] and s1[i - 1] == s3[i - 1]
        for j in range(1, n + 1):
            dp[j] = (dp[j] and s1[i - 1] == s3[i + j - 1]) or \
                    (dp[j - 1] and s2[j - 1] == s3[i + j - 1])
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
    assert is_interleave("aabcc", "dbbca", "aadbbcbcac") is True
    assert is_interleave("aabcc", "dbbca", "aadbbbaccc") is False
    assert is_interleave("", "", "") is True
    assert is_interleave("a", "", "a") is True
    assert is_interleave("", "b", "a") is False
    assert is_interleave("ab", "cd", "acbd") is True
    assert stdlib_only()
    print("dp-39 OK")


if __name__ == "__main__":
    main()
