"""lis-32: LIS with values restricted to [lo, hi].

Filter to the value window, then standard LIS.

Time complexity: O(n^2) time
Space complexity: O(n)"""

import ast
import sys
LIS_32_VERSION = "lis-32.v1"


def _check_seq(seq):
    """Validate seq is a list/tuple of numbers; return a list copy."""
    if not isinstance(seq, (list, tuple)):
        raise ValueError("seq must be a list or tuple")
    for x in seq:
        if not isinstance(x, (int, float)):
            raise ValueError("seq elements must be numbers")
    return list(seq)
def lis_in_range(seq, lo, hi):
    """LIS length using only values with lo <= x <= hi."""
    a = _check_seq(seq)
    if not isinstance(lo, (int, float)) or not isinstance(hi, (int, float)):
        raise ValueError("lo and hi must be numbers")
    if lo > hi:
        raise ValueError("lo must not exceed hi")
    b = [x for x in a if lo <= x <= hi]
    n = len(b)
    if n == 0:
        return 0
    dp = [1] * n
    for i in range(n):
        for j in range(i):
            if b[j] < b[i] and dp[j] + 1 > dp[i]:
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
    assert lis_in_range([5, 1, 4, 2, 3], 2, 4) == 2
    assert lis_in_range([1, 2, 3], 5, 9) == 0
    assert lis_in_range([1, 2, 3], 1, 3) == 3
    assert stdlib_only()
    print("lis-32 OK")


if __name__ == "__main__":
    main()
