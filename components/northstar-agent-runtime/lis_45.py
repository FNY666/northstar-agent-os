"""lis-45: Longest fixed-difference chain.

Each next element equals previous plus d (arithmetic subsequence).

Time complexity: O(n) time
Space complexity: O(n)"""

import ast
import sys
LIS_45_VERSION = "lis-45.v1"


def _check_seq(seq):
    """Validate seq is a list/tuple of numbers; return a list copy."""
    if not isinstance(seq, (list, tuple)):
        raise ValueError("seq must be a list or tuple")
    for x in seq:
        if not isinstance(x, (int, float)):
            raise ValueError("seq elements must be numbers")
    return list(seq)
def longest_diff_d_chain(seq, d):
    """Longest subsequence where each step adds exactly d."""
    a = _check_seq(seq)
    if not isinstance(d, (int, float)):
        raise ValueError("d must be a number")
    dp = {}
    best = 0
    for x in a:
        cur = dp.get(x - d, 0) + 1
        if cur > dp.get(x, 0):
            dp[x] = cur
        if cur > best:
            best = cur
    return best

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
    assert longest_diff_d_chain([1, 3, 5, 7], 2) == 4
    assert longest_diff_d_chain([1, 2, 3, 4, 5], 2) == 3
    assert longest_diff_d_chain([], 2) == 0
    assert stdlib_only()
    print("lis-45 OK")


if __name__ == "__main__":
    main()
