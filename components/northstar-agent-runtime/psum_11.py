"""psum_11: Maximum Subarray (Min-Prefix)

max subarray = max over i of (prefix[i] - min prefix before i); Kadane in disguise.

Time complexity: O(n) time
Space complexity: O(1)"""

import ast
import sys
PSUM_11_VERSION = "psum-11.v1"


def max_sub(a):
    best = -(10 ** 18)
    mn = 0
    s = 0
    for x in a:
        s += x
        if s - mn > best:
            best = s - mn
        if s < mn:
            mn = s
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
    assert max_sub([-2, 1, -3, 4, -1, 2, 1, -5, 4]) == 6
    assert max_sub([1]) == 1
    assert max_sub([-1, -2]) == -1
    assert max_sub([5, 4, -1, 7, 8]) == 23
    assert stdlib_only()
    print("psum_11 OK")


if __name__ == "__main__":
    main()
