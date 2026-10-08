"""dp-09: Longest common subsequence (length).

Length of the longest subsequence common to both strings. Two rolling rows keep memory linear.

Time complexity: O(m*n) time
Space complexity: O(n) space
"""

import ast
import sys

DP_09_VERSION = "dp-09.v1"


def lcs(a: str, b: str) -> int:
    """Return the length of the longest common subsequence of a and b."""
    m, n = len(a), len(b)
    prev = [0] * (n + 1)
    for i in range(1, m + 1):
        cur = [0] * (n + 1)
        ai = a[i - 1]
        for j in range(1, n + 1):
            if ai == b[j - 1]:
                cur[j] = prev[j - 1] + 1
            else:
                cur[j] = prev[j] if prev[j] >= cur[j - 1] else cur[j - 1]
        prev = cur
    return prev[n]


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
    assert lcs("abcde", "ace") == 3
    assert lcs("abc", "abc") == 3
    assert lcs("abc", "def") == 0
    assert lcs("", "abc") == 0
    assert lcs("abc", "") == 0
    assert lcs("ezupkr", "ubmrapg") == 2
    assert stdlib_only()
    print("dp-09 OK")


if __name__ == "__main__":
    main()
