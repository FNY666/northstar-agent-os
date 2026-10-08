"""dp-19: Distinct subsequences.

Count how many times t appears as a subsequence of s. dp[j] accumulates matches scanning s once per row, backwards.

Time complexity: O(m*n) time
Space complexity: O(n) space
"""

import ast
import sys

DP_19_VERSION = "dp-19.v1"


def distinct_subseq(s: str, t: str) -> int:
    """Return the number of distinct subsequences of s equal to t."""
    m, n = len(s), len(t)
    dp = [0] * (n + 1)
    dp[0] = 1
    for i in range(1, m + 1):
        for j in range(n, 0, -1):
            if s[i - 1] == t[j - 1]:
                dp[j] += dp[j - 1]
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
    assert distinct_subseq("rabbbit", "rabbit") == 3
    assert distinct_subseq("babgbag", "bag") == 5
    assert distinct_subseq("abc", "") == 1
    assert distinct_subseq("", "a") == 0
    assert distinct_subseq("", "") == 1
    assert distinct_subseq("aaa", "aa") == 3
    assert stdlib_only()
    print("dp-19 OK")


if __name__ == "__main__":
    main()
