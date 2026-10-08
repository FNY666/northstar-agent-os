"""dp-17: Longest palindromic subsequence.

Length of the longest subsequence that reads the same forwards and backwards. Interval DP over substring length.

Time complexity: O(n^2) time
Space complexity: O(n^2) space
"""

import ast
import sys

DP_17_VERSION = "dp-17.v1"


def lps(s: str) -> int:
    """Return the length of the longest palindromic subsequence of s."""
    n = len(s)
    if n == 0:
        return 0
    dp = [[0] * n for _ in range(n)]
    for i in range(n):
        dp[i][i] = 1
    for length in range(2, n + 1):
        for i in range(n - length + 1):
            j = i + length - 1
            if s[i] == s[j]:
                dp[i][j] = 2 if length == 2 else dp[i + 1][j - 1] + 2
            else:
                dp[i][j] = max(dp[i + 1][j], dp[i][j - 1])
    return dp[0][n - 1]


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
    assert lps("bbbab") == 4
    assert lps("cbbd") == 2
    assert lps("a") == 1
    assert lps("") == 0
    assert lps("character") == 5
    assert lps("ab") == 1
    assert stdlib_only()
    print("dp-17 OK")


if __name__ == "__main__":
    main()
