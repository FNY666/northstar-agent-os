"""lis-43: Count of longest decreasing subsequences.

Mirror of the LIS counter with the decreasing relation.

Time complexity: O(n^2) time
Space complexity: O(n)"""

import ast
import sys
LIS_43_VERSION = "lis-43.v1"


def _check_seq(seq):
    """Validate seq is a list/tuple of numbers; return a list copy."""
    if not isinstance(seq, (list, tuple)):
        raise ValueError("seq must be a list or tuple")
    for x in seq:
        if not isinstance(x, (int, float)):
            raise ValueError("seq elements must be numbers")
    return list(seq)
def count_lds(seq):
    """Number of distinct longest strictly decreasing subsequences."""
    a = _check_seq(seq)
    n = len(a)
    if n == 0:
        return 0
    length = [1] * n
    count = [1] * n
    for i in range(n):
        for j in range(i):
            if a[j] > a[i]:
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
    assert count_lds([3, 2, 2, 1]) == 2
    assert count_lds([5, 4, 3, 2, 1]) == 1
    assert count_lds([]) == 0
    assert stdlib_only()
    print("lis-43 OK")


if __name__ == "__main__":
    main()
