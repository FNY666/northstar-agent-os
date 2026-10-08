"""lis-07: Count of longest increasing subsequences.

DP tracking both best length and number of ways (LeetCode 673).

Time complexity: O(n^2) time
Space complexity: O(n)"""

import ast
import sys
LIS_07_VERSION = "lis-07.v1"


def _check_seq(seq):
    """Validate seq is a list/tuple of numbers; return a list copy."""
    if not isinstance(seq, (list, tuple)):
        raise ValueError("seq must be a list or tuple")
    for x in seq:
        if not isinstance(x, (int, float)):
            raise ValueError("seq elements must be numbers")
    return list(seq)
def count_lis(seq):
    """Number of distinct longest strictly increasing subsequences."""
    a = _check_seq(seq)
    n = len(a)
    if n == 0:
        return 0
    length = [1] * n
    count = [1] * n
    for i in range(n):
        for j in range(i):
            if a[j] < a[i]:
                if length[j] + 1 > length[i]:
                    length[i] = length[j] + 1
                    count[i] = count[j]
                elif length[j] + 1 == length[i]:
                    count[i] += count[j]
    m = max(length)
    return sum(c for l, c in zip(length, count) if l == m)

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
    assert count_lis([1, 3, 5, 4, 7]) == 2
    assert count_lis([2, 2, 2, 2, 2]) == 5
    assert count_lis([]) == 0
    assert stdlib_only()
    print("lis-07 OK")


if __name__ == "__main__":
    main()
