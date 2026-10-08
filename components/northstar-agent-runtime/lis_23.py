"""lis-23: Count of all strictly increasing subsequences.

DP counting every increasing subsequence, singletons included.

Time complexity: O(n^2) time
Space complexity: O(n)"""

import ast
import sys
LIS_23_VERSION = "lis-23.v1"


def _check_seq(seq):
    """Validate seq is a list/tuple of numbers; return a list copy."""
    if not isinstance(seq, (list, tuple)):
        raise ValueError("seq must be a list or tuple")
    for x in seq:
        if not isinstance(x, (int, float)):
            raise ValueError("seq elements must be numbers")
    return list(seq)
def count_increasing_subseqs(seq):
    """Total number of strictly increasing subsequences (non-empty)."""
    a = _check_seq(seq)
    n = len(a)
    dp = [1] * n
    for i in range(n):
        for j in range(i):
            if a[j] < a[i]:
                dp[i] += dp[j]
    return sum(dp)

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
    assert count_increasing_subseqs([1, 2, 3]) == 7
    assert count_increasing_subseqs([3, 2, 1]) == 3
    assert count_increasing_subseqs([]) == 0
    assert stdlib_only()
    print("lis-23 OK")


if __name__ == "__main__":
    main()
