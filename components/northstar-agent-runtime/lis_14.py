"""lis-14: LIS length starting at each position.

Reverse DP: best increasing length of a subsequence starting at i.

Time complexity: O(n^2) time
Space complexity: O(n)"""

import ast
import sys
LIS_14_VERSION = "lis-14.v1"


def _check_seq(seq):
    """Validate seq is a list/tuple of numbers; return a list copy."""
    if not isinstance(seq, (list, tuple)):
        raise ValueError("seq must be a list or tuple")
    for x in seq:
        if not isinstance(x, (int, float)):
            raise ValueError("seq elements must be numbers")
    return list(seq)
def lis_starting_at(seq):
    """List where entry i is the LIS length of a subsequence starting at i."""
    a = _check_seq(seq)
    n = len(a)
    dp = [1] * n
    for i in range(n - 1, -1, -1):
        for j in range(i + 1, n):
            if a[j] > a[i] and dp[j] + 1 > dp[i]:
                dp[i] = dp[j] + 1
    return dp

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
    assert lis_starting_at([10, 9, 2, 5, 3, 7, 101, 18]) == [2, 2, 4, 3, 3, 2, 1, 1]
    assert lis_starting_at([]) == []
    assert lis_starting_at([1, 2, 3]) == [3, 2, 1]
    assert stdlib_only()
    print("lis-14 OK")


if __name__ == "__main__":
    main()
