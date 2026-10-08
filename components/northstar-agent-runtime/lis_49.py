"""lis-49: LIS of length exactly K.

Return one increasing subsequence of exactly length k, or None.

Time complexity: O(n^2) time
Space complexity: O(n)"""

import ast
import sys
LIS_49_VERSION = "lis-49.v1"


def _check_seq(seq):
    """Validate seq is a list/tuple of numbers; return a list copy."""
    if not isinstance(seq, (list, tuple)):
        raise ValueError("seq must be a list or tuple")
    for x in seq:
        if not isinstance(x, (int, float)):
            raise ValueError("seq elements must be numbers")
    return list(seq)
def lis_exact_k(seq, k):
    """One strictly increasing subsequence of length exactly k (or None)."""
    a = _check_seq(seq)
    if not isinstance(k, int):
        raise ValueError("k must be an int")
    if k < 0:
        raise ValueError("k must be non-negative")
    n = len(a)
    if k == 0:
        return []
    if n == 0:
        return None
    dp = [1] * n
    prev = [-1] * n
    for i in range(n):
        for j in range(i):
            if a[j] < a[i] and dp[j] + 1 > dp[i]:
                dp[i] = dp[j] + 1
                prev[i] = j
    idx = next((i for i in range(n) if dp[i] >= k), None)
    if idx is None:
        return None
    chain = []
    cur = idx
    while cur != -1:
        chain.append(a[cur])
        cur = prev[cur]
    chain.reverse()
    return chain[-k:]

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
    r = lis_exact_k([10, 9, 2, 5, 3, 7, 101, 18], 4)
    assert r is not None and len(r) == 4 and all(r[i] < r[i+1] for i in range(3))
    assert lis_exact_k([1, 2, 3], 5) is None
    assert lis_exact_k([1, 2, 3], 0) == []
    assert stdlib_only()
    print("lis-49 OK")


if __name__ == "__main__":
    main()
