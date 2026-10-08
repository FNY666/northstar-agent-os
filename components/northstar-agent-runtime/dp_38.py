"""dp-38: Delete operation for two strings.

Minimum deletions making a and b equal (delete from either string). Equals |a| + |b| - 2 * LCS(a, b); computed directly.

Time complexity: O(m*n) time
Space complexity: O(n) space
"""

import ast
import sys

DP_38_VERSION = "dp-38.v1"


def min_delete(a: str, b: str) -> int:
    """Return the minimum deletions to make a and b equal."""
    m, n = len(a), len(b)
    prev = list(range(n + 1))
    for i in range(1, m + 1):
        cur = [i] + [0] * n
        for j in range(1, n + 1):
            if a[i - 1] == b[j - 1]:
                cur[j] = prev[j - 1]
            else:
                cur[j] = 1 + min(prev[j], cur[j - 1])
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
    assert min_delete("sea", "eat") == 2
    assert min_delete("leetcode", "etco") == 4
    assert min_delete("abc", "abc") == 0
    assert min_delete("", "abc") == 3
    assert min_delete("abc", "") == 3
    assert min_delete("a", "b") == 2
    assert stdlib_only()
    print("dp-38 OK")


if __name__ == "__main__":
    main()
