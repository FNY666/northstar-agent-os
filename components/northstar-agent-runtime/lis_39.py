"""lis-39: LIS by custom key function.

Order elements by key(x) instead of raw value comparison.

Time complexity: O(n^2) time
Space complexity: O(n)"""

import ast
import sys
LIS_39_VERSION = "lis-39.v1"


def _check_key_seq(seq):
    """Validate seq is a list/tuple; return a list copy."""
    if not isinstance(seq, (list, tuple)):
        raise ValueError("seq must be a list or tuple")
    return list(seq)
def lis_by_key(seq, key):
    """LIS length where order is defined by key(x) strictly increasing."""
    a = _check_key_seq(seq)
    if not callable(key):
        raise ValueError("key must be callable")
    keys = [key(x) for x in a]
    n = len(a)
    if n == 0:
        return 0
    dp = [1] * n
    for i in range(n):
        for j in range(i):
            if keys[j] < keys[i] and dp[j] + 1 > dp[i]:
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
    assert lis_by_key([-3, -1, -2], key=abs) == 2
    assert lis_by_key(["aa", "b", "cccc"], key=len) == 2
    assert lis_by_key([], key=abs) == 0
    assert stdlib_only()
    print("lis-39 OK")


if __name__ == "__main__":
    main()
