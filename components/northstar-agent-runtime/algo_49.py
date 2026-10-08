"""Palindrome partitioning (minimum cuts) via dynamic programming.

First build a palindrome table:

    pal[i][j] = (s[i] == s[j]) and (j - i < 2 or pal[i+1][j-1])

Then the cut count for prefix s[:i+1]:

    cuts[i] = 0                        if pal[0][i]
    cuts[i] = min over j<i of cuts[j] + 1  for j with pal[j+1][i]

Time O(n^2), space O(n^2). Returns 0 for strings of length <= 1.
"""

import ast
import sys
from pathlib import Path

ALGO_49_VERSION = "algo-49.v1"

STDLIB_USED = frozenset({"ast", "pathlib", "sys"})


def stdlib_only() -> bool:
    """Parse this file with ``ast`` and assert every imported top-level module
    is one this module actually uses from the standard library."""
    tree = ast.parse(Path(__file__).read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imported.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imported.add(node.module.split(".")[0])
    stdlib_names = set(sys.stdlib_module_names)
    for name in sorted(imported):
        assert name in stdlib_names, "non-stdlib import: %s" % name
        assert name in STDLIB_USED, "imported but unused module: %s" % name
    assert set(STDLIB_USED) == imported, (
        "import drift: declared %s vs found %s"
        % (sorted(STDLIB_USED), sorted(imported))
    )
    return True


def min_cuts(s: str) -> int:
    """Return the minimum cuts so every piece of ``s`` is a palindrome."""
    n = len(s)
    if n <= 1:
        return 0
    pal = [[False] * n for _ in range(n)]
    for i in range(n):
        pal[i][i] = True
    for length in range(2, n + 1):
        for i in range(n - length + 1):
            j = i + length - 1
            pal[i][j] = s[i] == s[j] and (length == 2 or pal[i + 1][j - 1])
    cuts = list(range(n))
    for i in range(n):
        if pal[0][i]:
            cuts[i] = 0
        else:
            cuts[i] = min(cuts[j] + 1 for j in range(i) if pal[j + 1][i])
    return cuts[n - 1]


def main() -> None:
    assert min_cuts("aab") == 1
    assert min_cuts("") == 0
    assert min_cuts("a") == 0
    assert min_cuts("aba") == 0
    assert min_cuts("ab") == 1
    assert min_cuts("abcbm") == 2  # a | bcb | m
    assert min_cuts("aaaa") == 0
    assert min_cuts("abcde") == 4
    assert stdlib_only()
    print("algo-49 OK")


if __name__ == "__main__":
    main()
