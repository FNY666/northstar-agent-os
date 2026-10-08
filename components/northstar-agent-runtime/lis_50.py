"""lis-50: Maximum sum increasing subsequence with path.

Returns (best_sum, one achieving subsequence).

Time complexity: O(n^2) time
Space complexity: O(n)"""

import ast
import sys
LIS_50_VERSION = "lis-50.v1"


def _check_seq(seq):
    """Validate seq is a list/tuple of numbers; return a list copy."""
    if not isinstance(seq, (list, tuple)):
        raise ValueError("seq must be a list or tuple")
    for x in seq:
        if not isinstance(x, (int, float)):
            raise ValueError("seq elements must be numbers")
    return list(seq)
def max_sum_increasing_with_path(seq):
    """(max sum, one max-sum strictly increasing subsequence)."""
    a = _check_seq(seq)
    n = len(a)
    if n == 0:
        return (0, [])
    dp = list(a)
    prev = [-1] * n
    for i in range(n):
        for j in range(i):
            if a[j] < a[i] and dp[j] + a[i] > dp[i]:
                dp[i] = dp[j] + a[i]
                prev[i] = j
    k = max(range(n), key=lambda i: dp[i])
    out = []
    cur = k
    while cur != -1:
        out.append(a[cur])
        cur = prev[cur]
    out.reverse()
    return (dp[k], out)

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
    s, p = max_sum_increasing_with_path([1, 101, 2, 3, 100, 4, 5])
    assert s == 106 and p == [1, 2, 3, 100]
    assert max_sum_increasing_with_path([]) == (0, [])
    assert stdlib_only()
    print("lis-50 OK")


if __name__ == "__main__":
    main()
