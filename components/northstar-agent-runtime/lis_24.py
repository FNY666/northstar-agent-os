"""lis-24: Lexicographically smallest LIS.

Greedy smallest feasible value using suffix LIS lengths.

Time complexity: O(n^2) time
Space complexity: O(n)"""

import ast
import sys
LIS_24_VERSION = "lis-24.v1"


def _check_seq(seq):
    """Validate seq is a list/tuple of numbers; return a list copy."""
    if not isinstance(seq, (list, tuple)):
        raise ValueError("seq must be a list or tuple")
    for x in seq:
        if not isinstance(x, (int, float)):
            raise ValueError("seq elements must be numbers")
    return list(seq)
def smallest_lis(seq):
    """Lexicographically smallest longest increasing subsequence."""
    a = _check_seq(seq)
    n = len(a)
    if n == 0:
        return []
    dp = [1] * n
    for i in range(n - 1, -1, -1):
        for j in range(i + 1, n):
            if a[j] > a[i] and dp[j] + 1 > dp[i]:
                dp[i] = dp[j] + 1
    L = max(dp)
    res = []
    prev_val = None
    prev_idx = -1
    for _ in range(L):
        best_val = None
        best_idx = -1
        for i in range(prev_idx + 1, n):
            if (prev_val is None or a[i] > prev_val) and dp[i] == L - len(res):
                if best_val is None or a[i] < best_val:
                    best_val = a[i]
                    best_idx = i
        res.append(best_val)
        prev_val = best_val
        prev_idx = best_idx
    return res

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
    assert smallest_lis([10, 9, 2, 5, 3, 7, 101, 18]) == [2, 3, 7, 18]
    assert smallest_lis([3, 1, 2]) == [1, 2]
    assert smallest_lis([]) == []
    assert stdlib_only()
    print("lis-24 OK")


if __name__ == "__main__":
    main()
