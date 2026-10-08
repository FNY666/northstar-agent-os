"""psum_09: Pivot / Equilibrium Index

Total sum plus a running left sum finds the index where left == right in O(n).

Time complexity: O(n) time
Space complexity: O(1)"""

import ast
import sys
PSUM_09_VERSION = "psum-09.v1"


def pivot(a):
    """Index i with sum(a[:i]) == sum(a[i+1:]); -1 if none."""
    total = sum(a)
    left = 0
    for i, x in enumerate(a):
        if left == total - left - x:
            return i
        left += x
    return -1

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
    assert pivot([1, 7, 3, 6, 5, 6]) == 3
    assert pivot([1, 2, 3]) == -1
    assert pivot([2, 1, -1]) == 0
    assert pivot([]) == -1
    assert pivot([0]) == 0
    assert stdlib_only()
    print("psum_09 OK")


if __name__ == "__main__":
    main()
