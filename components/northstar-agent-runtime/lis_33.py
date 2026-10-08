"""lis-33: Longest valley subsequence.

Strictly decreasing then strictly increasing around a bottom.

Time complexity: O(n^2) time
Space complexity: O(n)"""

import ast
import sys
LIS_33_VERSION = "lis-33.v1"


def _check_seq(seq):
    """Validate seq is a list/tuple of numbers; return a list copy."""
    if not isinstance(seq, (list, tuple)):
        raise ValueError("seq must be a list or tuple")
    for x in seq:
        if not isinstance(x, (int, float)):
            raise ValueError("seq elements must be numbers")
    return list(seq)
def longest_valley(seq):
    """Length of the longest valley (down then up) subsequence."""
    a = _check_seq(seq)
    n = len(a)
    if n == 0:
        return 0
    dec_end = [1] * n
    for i in range(n):
        for j in range(i):
            if a[j] > a[i] and dec_end[j] + 1 > dec_end[i]:
                dec_end[i] = dec_end[j] + 1
    inc_start = [1] * n
    for i in range(n - 1, -1, -1):
        for j in range(i + 1, n):
            if a[j] > a[i] and inc_start[j] + 1 > inc_start[i]:
                inc_start[i] = inc_start[j] + 1
    return max(dec_end[i] + inc_start[i] - 1 for i in range(n))

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
    assert longest_valley([5, 3, 1, 2, 4]) == 5
    assert longest_valley([1, 2, 3]) == 3
    assert longest_valley([]) == 0
    assert stdlib_only()
    print("lis-33 OK")


if __name__ == "__main__":
    main()
