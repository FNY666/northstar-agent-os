"""dp-12: Palindrome partitioning (minimum cuts).

Fewest cuts so every piece is a palindrome. Precompute palindromic substrings, then cut DP.

Time complexity: O(n^2) time
Space complexity: O(n^2) space
"""

import ast
import sys

DP_12_VERSION = "dp-12.v1"


def min_cuts(s: str) -> int:
    """Return the minimum cuts needed to partition s into palindromes."""
    n = len(s)
    if n <= 1:
        return 0
    is_pal = [[False] * n for _ in range(n)]
    for i in range(n):
        is_pal[i][i] = True
    for length in range(2, n + 1):
        for i in range(n - length + 1):
            j = i + length - 1
            is_pal[i][j] = s[i] == s[j] and (length == 2 or is_pal[i + 1][j - 1])
    cuts = list(range(n))
    for i in range(n):
        if is_pal[0][i]:
            cuts[i] = 0
        else:
            for j in range(i):
                if is_pal[j + 1][i]:
                    cuts[i] = min(cuts[i], cuts[j] + 1)
    return cuts[n - 1]


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
    assert min_cuts("aab") == 1
    assert min_cuts("a") == 0
    assert min_cuts("") == 0
    assert min_cuts("ab") == 1
    assert min_cuts("aba") == 0
    assert min_cuts("abccbc") == 2
    assert stdlib_only()
    print("dp-12 OK")


if __name__ == "__main__":
    main()
