"""lis-40: LIS over characters of a string.

Strictly increasing by Unicode code point.

Time complexity: O(n^2) time
Space complexity: O(n)"""

import ast
import sys
LIS_40_VERSION = "lis-40.v1"



def lis_string(s):
    """Length of the longest strictly increasing character subsequence."""
    if not isinstance(s, str):
        raise ValueError("input must be a string")
    a = [ord(c) for c in s]
    n = len(a)
    if n == 0:
        return 0
    dp = [1] * n
    for i in range(n):
        for j in range(i):
            if a[j] < a[i] and dp[j] + 1 > dp[i]:
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
    assert lis_string("abcde") == 5
    assert lis_string("edcba") == 1
    assert lis_string("") == 0
    assert stdlib_only()
    print("lis-40 OK")


if __name__ == "__main__":
    main()
