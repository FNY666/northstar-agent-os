"""lis-12: Longest alternating (wiggle) subsequence.

Greedy up/down counters; equal neighbours contribute nothing.

Time complexity: O(n) time
Space complexity: O(1)"""

import ast
import sys
LIS_12_VERSION = "lis-12.v1"


def _check_seq(seq):
    """Validate seq is a list/tuple of numbers; return a list copy."""
    if not isinstance(seq, (list, tuple)):
        raise ValueError("seq must be a list or tuple")
    for x in seq:
        if not isinstance(x, (int, float)):
            raise ValueError("seq elements must be numbers")
    return list(seq)
def longest_wiggle(seq):
    """Length of the longest alternating up/down subsequence."""
    a = _check_seq(seq)
    n = len(a)
    if n < 2:
        return n
    up = down = 1
    for i in range(1, n):
        if a[i] > a[i - 1]:
            up = down + 1
        elif a[i] < a[i - 1]:
            down = up + 1
    return up if up > down else down

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
    assert longest_wiggle([1, 7, 4, 9, 2, 5]) == 6
    assert longest_wiggle([1, 2, 3, 4, 5]) == 2
    assert longest_wiggle([]) == 0
    assert stdlib_only()
    print("lis-12 OK")


if __name__ == "__main__":
    main()
