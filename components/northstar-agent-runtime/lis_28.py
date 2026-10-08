"""lis-28: Longest mountain subsequence (proper).

Strictly up then strictly down, both sides non-trivial.

Time complexity: O(n^2) time
Space complexity: O(n)"""

import ast
import sys
LIS_28_VERSION = "lis-28.v1"


def _check_seq(seq):
    """Validate seq is a list/tuple of numbers; return a list copy."""
    if not isinstance(seq, (list, tuple)):
        raise ValueError("seq must be a list or tuple")
    for x in seq:
        if not isinstance(x, (int, float)):
            raise ValueError("seq elements must be numbers")
    return list(seq)
def longest_mountain_subseq(seq):
    """Length of the longest proper mountain subsequence (0 if none)."""
    a = _check_seq(seq)
    n = len(a)
    if n < 3:
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
    best = 0
    for i in range(n):
        if inc[i] > 1 and dec[i] > 1:
            tot = inc[i] + dec[i] - 1
            if tot > best:
                best = tot
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
    assert longest_mountain_subseq([2, 1, 4, 7, 3, 2, 5]) == 5
    assert longest_mountain_subseq([1, 2, 1]) == 3
    assert longest_mountain_subseq([1, 2, 3, 4]) == 0
    assert stdlib_only()
    print("lis-28 OK")


if __name__ == "__main__":
    main()
