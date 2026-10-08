"""lis-44: Longest even/odd alternating subsequence.

DP where consecutive parities must differ.

Time complexity: O(n^2) time
Space complexity: O(n)"""

import ast
import sys
LIS_44_VERSION = "lis-44.v1"


def _check_seq(seq):
    """Validate seq is a list/tuple of numbers; return a list copy."""
    if not isinstance(seq, (list, tuple)):
        raise ValueError("seq must be a list or tuple")
    for x in seq:
        if not isinstance(x, (int, float)):
            raise ValueError("seq elements must be numbers")
    return list(seq)
def longest_parity_alternating(seq):
    """Longest subsequence alternating even and odd values."""
    a = _check_seq(seq)
    n = len(a)
    if n == 0:
        return 0
    dp = [1] * n
    for i in range(n):
        pi = a[i] % 2
        for j in range(i):
            if a[j] % 2 != pi and dp[j] + 1 > dp[i]:
                dp[i] = dp[j] + 1
    return max(dp)

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
    assert longest_parity_alternating([1, 2, 3, 4]) == 4
    assert longest_parity_alternating([2, 4, 6]) == 1
    assert longest_parity_alternating([]) == 0
    assert stdlib_only()
    print("lis-44 OK")


if __name__ == "__main__":
    main()
