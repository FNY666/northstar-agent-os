"""lis-08: Longest bitonic subsequence.

Strictly increasing then strictly decreasing; peak counted once.

Time complexity: O(n^2) time
Space complexity: O(n)"""

import ast
import sys
LIS_08_VERSION = "lis-08.v1"


def _check_seq(seq):
    """Validate seq is a list/tuple of numbers; return a list copy."""
    if not isinstance(seq, (list, tuple)):
        raise ValueError("seq must be a list or tuple")
    for x in seq:
        if not isinstance(x, (int, float)):
            raise ValueError("seq elements must be numbers")
    return list(seq)
def longest_bitonic(seq):
    """Length of the longest bitonic (up then down) subsequence."""
    a = _check_seq(seq)
    n = len(a)
    if n == 0:
        return 0
    inc = [1] * n
    for i in range(n):
        for j in range(i):
            if a[j] < a[i] and inc[j] + 1 > inc[i]:
                inc[i] = inc[j] + 1
    dec = [1] * n
    for i in range(n - 1, -1, -1):
        for j in range(i + 1, n):
            if a[j] < a[i] and dec[j] + 1 > dec[i]:
                dec[i] = dec[j] + 1
    return max(inc[i] + dec[i] - 1 for i in range(n))

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
    assert longest_bitonic([1, 11, 2, 10, 4, 5, 2, 1]) == 6
    assert longest_bitonic([1, 2, 3]) == 3
    assert longest_bitonic([]) == 0
    assert stdlib_only()
    print("lis-08 OK")


if __name__ == "__main__":
    main()
