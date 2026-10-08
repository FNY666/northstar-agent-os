"""dp-18: Longest palindromic substring.

Return the longest substring that reads the same forwards and backwards. Table of palindromic intervals by increasing length.

Time complexity: O(n^2) time
Space complexity: O(n^2) space
"""

import ast
import sys

DP_18_VERSION = "dp-18.v1"


def longest_pal_substr(s: str) -> str:
    """Return the longest palindromic substring of s."""
    n = len(s)
    if n == 0:
        return ""
    start, best = 0, 1
    is_pal = [[False] * n for _ in range(n)]
    for i in range(n):
        is_pal[i][i] = True
    for i in range(n - 1):
        if s[i] == s[i + 1]:
            is_pal[i][i + 1] = True
            start, best = i, 2
    for length in range(3, n + 1):
        for i in range(n - length + 1):
            j = i + length - 1
            if s[i] == s[j] and is_pal[i + 1][j - 1]:
                is_pal[i][j] = True
                if length > best:
                    start, best = i, length
    return s[start:start + best]


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
    assert longest_pal_substr("babad") in ("bab", "aba")
    assert longest_pal_substr("cbbd") == "bb"
    assert longest_pal_substr("a") == "a"
    assert longest_pal_substr("") == ""
    assert longest_pal_substr("ac") in ("a", "c")
    assert longest_pal_substr("forgeeksskeegfor") == "geeksskeeg"
    assert stdlib_only()
    print("dp-18 OK")


if __name__ == "__main__":
    main()
