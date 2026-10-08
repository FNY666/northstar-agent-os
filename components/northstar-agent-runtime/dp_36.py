"""dp-36: Longest common substring.

Length of the longest substring common to both strings. Unlike the subsequence variant, matches must be contiguous.

Time complexity: O(m*n) time
Space complexity: O(n) space
"""

import ast
import sys

DP_36_VERSION = "dp-36.v1"


def lc_substr(a: str, b: str) -> int:
    """Return the length of the longest common substring of a and b."""
    m, n = len(a), len(b)
    best = 0
    prev = [0] * (n + 1)
    for i in range(1, m + 1):
        cur = [0] * (n + 1)
        for j in range(1, n + 1):
            if a[i - 1] == b[j - 1]:
                cur[j] = prev[j - 1] + 1
                best = max(best, cur[j])
        prev = cur
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
    assert lc_substr("abcde", "abfce") == 2
    assert lc_substr("abcdxyz", "xyzabcd") == 4
    assert lc_substr("abc", "def") == 0
    assert lc_substr("", "abc") == 0
    assert lc_substr("abc", "abc") == 3
    assert lc_substr("zxabcdezy", "yzabcdezx") == 6
    assert stdlib_only()
    print("dp-36 OK")


if __name__ == "__main__":
    main()
